// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Output selection through the COMPILED BINARY: each source (flag,
//! environment, configuration file) selects the JSON format, and a malformed
//! value from each is refused with its own text and status 2, never accepted.
//! The refusal text is asserted, not only the exit code, and each valid case
//! is paired with the malformed one that differs from it in one value.
//!
//! The logging selection rows use `gran thresh <file>` for local file reads.
//! Its only log line is the `log.config` event every run emits at startup
//! at DEBUG, so a test that reads it raises the filter and a run at the
//! default filter writes nothing.

#![cfg(unix)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

struct ScratchDir(PathBuf);

impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because the preimage of a \
                      hashed or signed value must take a `WriterIdentity` instead. Here it is a SCRATCH-DIRECTORY NAME \
                      and nothing else (`granary-logging-cli-<pid>-<counter>` under the temp dir, created and removed \
                      by this fixture); the counter beside it is per-process, so without the pid two concurrent runs \
                      would share one directory. It reaches no hashed or signed value, and no assertion reads it"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-logging-cli-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Configure `gran <args>` with no logging variable inherited, then the given ones.
fn gran_command(args: &[&str], env: &[(&str, &str)]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_gran"));
    // Text on standard error is coloured unless NO_COLOR is set, even into a
    // pipe; the assertions read plain text.
    command.env("NO_COLOR", "1");
    for name in [
        "RUST_LOG",
        "GRANARY_LOG_FORMAT",
        "GRANARY_LOG_FILE",
        "GRANARY_LOG_FILTER",
        "GRANARY_LOG_CONFIG",
        "GRANARY_LOG_PATHS",
    ] {
        command.env_remove(name);
    }
    command.args(args).envs(env.iter().copied());
    command
}

fn gran(args: &[&str], env: &[(&str, &str)]) -> Output {
    gran_command(args, env)
        .output()
        .unwrap_or_else(|e| panic!("gran did not run: {e}"))
}

#[test]
fn cat_and_verify_argument_refusals_preserve_usage_exit_when_stderr_fails() {
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };

    let usage = gran(&[], &[]);
    assert_eq!(usage.status.code(), Some(2));
    assert!(usage.stderr.starts_with(b"usage: gran "));
    let mut failed_stream_results = Vec::new();
    for (verb, diagnostic) in [
        (
            "cat",
            "gran cat: expected 2 positional arguments (volume, path), got 0\n",
        ),
        (
            "verify",
            "gran verify: expected 1 positional argument (store-or-cache root), got 0\n",
        ),
    ] {
        let healthy = gran(&[verb], &[]);
        assert_eq!(healthy.status.code(), Some(2), "{verb}");
        assert!(healthy.stdout.is_empty(), "{verb}");
        assert_eq!(
            healthy.stderr,
            [diagnostic.as_bytes(), &usage.stderr].concat(),
            "{verb}"
        );

        let (stderr, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let failed = gran_command(&[verb], &[])
            .stderr(Stdio::from(OwnedFd::from(stderr)))
            .output()
            .unwrap();
        failed_stream_results.push((verb, failed.status.code(), failed.stdout.is_empty()));
    }
    assert_eq!(
        failed_stream_results,
        [("cat", Some(2), true), ("verify", Some(2), true)]
    );
}

#[expect(
    clippy::unwrap_used,
    reason = "construct a private overlay test fixture"
)]
fn plant_overlay(root: &Path, scope: &str, torn: bool) -> PathBuf {
    use granary_client::{OverlayDisk, OverlayIo as _};
    use granary_core::{
        hash::GrainId,
        manifest::Name,
        overlay_journal::{
            CreateKind, JournalHeader, Location, Parent, Record, WriterRecord, encode_journal,
        },
        root::VolumeName,
    };
    use std::os::unix::fs::MetadataExt as _;

    drop(granary_client::Store::open(root).unwrap());
    let uid = fs::symlink_metadata(root).unwrap().uid();
    let parent = root.join("overlay").join(scope);
    let area = parent.join("vol");
    let mut disk = OverlayDisk::new(root, uid);
    for path in [
        root.join("overlay"),
        parent,
        area.clone(),
        area.join("staging"),
    ] {
        disk.create_directory(&path).unwrap();
    }
    let writer = WriterRecord {
        writer: [2; 16],
        volume: VolumeName::new("vol".into()).unwrap(),
        ceiling: 0,
    };
    let header = JournalHeader {
        writer: writer.writer,
        base_root: GrainId::of(b"test"),
        base_seq: 1,
        next_stage_id: 1,
        receipt_generation: 0,
    };
    let journal = if torn {
        let mut journal = header.encode().unwrap();
        journal.push(1);
        journal
    } else {
        let dirty = Record::Create {
            at: Location {
                parent: Parent::root(),
                name: Name::new(b"dirty".to_vec()).unwrap(),
            },
            kind: CreateKind::Dir,
        };
        encode_journal(&header, &[dirty]).unwrap()
    };
    for (leaf, bytes) in [("writer", writer.encode().unwrap()), ("journal", journal)] {
        let path = area.join(leaf);
        disk.create(&path).unwrap();
        disk.write_at(&path, 0, &bytes).unwrap();
    }
    area
}

#[test]
fn overlay_discard_plan_reports_a_failed_stdout() {
    use granary_core::overlay_discard::{Outcome, Row};
    use std::{
        os::{fd::OwnedFd, unix::net::UnixStream},
        process::Stdio,
    };

    let dir = ScratchDir::new();
    let root = dir.path().canonicalize().unwrap().join("store");
    let scope = "11".repeat(32);
    let journal = plant_overlay(&root, &scope, false).join("journal");
    let before = fs::read(&journal).unwrap();
    let args = [
        "overlay",
        "discard",
        "--plan",
        "--store-dir",
        root.to_str().unwrap(),
        "--scope",
        &scope,
        "--volume",
        "vol",
    ];

    let healthy = gran(&args, &[]);
    assert_eq!(healthy.status.code(), Some(0), "{}", text(&healthy.stderr));
    assert!(healthy.stderr.is_empty());
    let row = Row::parse(&healthy.stdout).unwrap();
    assert!(matches!(row.outcome, Outcome::Live(_)), "{row:?}");
    assert_eq!(healthy.stdout, row.to_string().as_bytes());

    let (stdout, peer) = UnixStream::pair().unwrap();
    drop(peer);
    let failed = gran_command(&args, &[])
        .stdout(Stdio::from(OwnedFd::from(stdout)))
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1), "{}", text(&failed.stderr));
    assert_eq!(failed.stderr, concat!(
        "gran overlay discard: OverlayDiscardDurability: output failed; retry with the same tuple\n",
        "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"overlay.discard_refused\",\"reason\":\"OverlayDiscardDurability\"}\n",
    ).as_bytes());
    assert_eq!(fs::read(&journal).unwrap(), before);
}

#[test]
fn overlay_custody_refusal_preserves_terminal_and_reports_a_closed_event() {
    use granary_core::overlay_discard::{Outcome, Row, hex};

    let dir = ScratchDir::new();
    let root = dir.path().canonicalize().unwrap().join("store");
    let scope = "11".repeat(32);
    let area = plant_overlay(&root, &scope, true);
    let selection = [
        "--store-dir",
        root.to_str().unwrap(),
        "--scope",
        &scope,
        "--volume",
        "vol",
    ];
    let log = dir.path().join("must-not-open.log");
    let settings = [
        ("GRANARY_LOG_FILE", log.to_str().unwrap()),
        ("GRANARY_LOG_FORMAT", "text"),
        ("RUST_LOG", "off"),
    ];
    let overlay = |verb: &str, options: &[&str]| {
        gran(
            &["overlay", verb]
                .into_iter()
                .chain(selection)
                .chain(options.iter().copied())
                .collect::<Vec<_>>(),
            &settings,
        )
    };
    let accepted = overlay("discard", &["--plan"]);
    assert_eq!(
        (accepted.status.code(), accepted.stderr.as_slice()),
        (Some(0), b"".as_slice())
    );
    let parsed = Row::parse(&accepted.stdout).unwrap();
    assert_eq!(accepted.stdout, parsed.to_string().as_bytes());

    fs::set_permissions(&area, fs::Permissions::from_mode(0o750)).unwrap();
    let refused = overlay("discard", &["--plan"]);
    assert_eq!(
        (refused.status.code(), refused.stdout.is_empty()),
        (Some(1), true)
    );
    assert_eq!(refused.stderr, concat!(
        "gran overlay discard: OverlayDiscardForeignCustody\n",
        "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"overlay.discard_refused\",\"reason\":\"OverlayDiscardForeignCustody\"}\n",
    ).as_bytes());
    assert!(!log.exists());

    fs::set_permissions(&area, fs::Permissions::from_mode(0o700)).unwrap();
    let writer = hex(&parsed.name.writer);
    let incarnation = hex(&parsed.name.incarnation);
    let tuple = ["--writer", &writer, "--journal-incarnation", &incarnation];
    let mut options = tuple.to_vec();
    options.extend(["--acknowledge-unsynced-loss", "--acknowledge-may-land"]);
    let moved = overlay("discard", &options);
    assert_eq!(
        (moved.status.code(), moved.stderr.as_slice()),
        (Some(0), b"".as_slice())
    );
    assert_eq!(Row::parse(&moved.stdout).unwrap().outcome, Outcome::Moved);

    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let publisher = format!("ed25519:{}", "44".repeat(32));
    let mut options = tuple.to_vec();
    options.extend([
        "--endpoint",
        "https://authority.invalid",
        "--pin",
        &pin,
        "--credential-context",
        "fixture",
        "--publisher-key",
        &publisher,
    ]);
    let unresolved = overlay("reconcile", &options);
    assert_eq!(
        (unresolved.status.code(), unresolved.stdout.is_empty()),
        (Some(1), true)
    );
    assert_eq!(unresolved.stderr, concat!(
        "gran overlay reconcile: OverlayArchiveUnresolved\n",
        "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"overlay.reconcile_refused\",\"reason\":\"OverlayArchiveUnresolved\"}\n",
    ).as_bytes());
    assert!(!log.exists());
}

#[test]
fn overlay_reconcile_settles_without_output_or_credentials() {
    assert_overlay_reconcile_settles(
        false,
        "gran overlay reconcile: no publications directory for the selected scope; settled with no retained records\n",
    );
}

#[test]
fn overlay_reconcile_settles_silently_with_complete_publication() {
    assert_overlay_reconcile_settles(true, "");
}

#[expect(
    clippy::unwrap_used,
    reason = "construct a private overlay and retained publication test fixture"
)]
fn assert_overlay_reconcile_settles(retain_publication: bool, expected_stderr: &str) {
    use granary_client::{Store, discard_overlay};
    use granary_core::{
        overlay_discard::{Outcome, hex, parse_hex},
        retained_submission,
        root::VolumeName,
    };
    use std::os::unix::fs::MetadataExt as _;

    let dir = ScratchDir::new();
    let root = dir.path().canonicalize().unwrap().join("store");
    let record = retain_publication.then(|| {
        retained_submission::decode(include_bytes!(
            "../../granary-core/tests/vectors/retained-submission/complete-chain.bin"
        ))
        .unwrap()
    });
    let scope = record
        .as_ref()
        .map_or_else(|| hex(&[0x11; 32]), |record| record.scope.digest().unwrap());
    let digest = parse_hex(&scope).unwrap();
    plant_overlay(&root, &scope, false);
    let volume = VolumeName::from_bytes(b"vol").unwrap();
    if let Some(record) = &record {
        let uid = fs::symlink_metadata(&root).unwrap().uid();
        Store::open(&root)
            .unwrap()
            .publications(uid)
            .unwrap()
            .begin(record)
            .unwrap();
    }
    let plan = discard_overlay(&root, digest, &volume, None).unwrap();
    let tuple = (plan.name.writer, plan.name.incarnation);
    let moved = discard_overlay(&root, digest, &volume, Some(tuple)).unwrap();
    let outcomes = (plan.outcome, moved.outcome);
    assert!(
        matches!(outcomes, (Outcome::Live(_), Outcome::Moved)),
        "{outcomes:?}"
    );
    let writer = hex(&tuple.0);
    let incarnation = hex(&tuple.1);
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let publisher = format!("ed25519:{}", "44".repeat(32));
    let cert = dir.path().join("missing-client-cert");
    let key = dir.path().join("missing-client-key");
    let settled = gran(
        &[
            "overlay",
            "reconcile",
            "--store-dir",
            root.to_str().unwrap(),
            "--scope",
            &scope,
            "--volume",
            volume.as_str(),
            "--writer",
            &writer,
            "--journal-incarnation",
            &incarnation,
            "--endpoint",
            "https://authority.invalid",
            "--pin",
            &pin,
            "--credential-context",
            "fixture",
            "--publisher-key",
            &publisher,
            "--client-cert",
            cert.to_str().unwrap(),
            "--client-key",
            key.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        (
            settled.status.code(),
            settled.stdout.as_slice(),
            text(&settled.stderr),
        ),
        (Some(0), b"".as_slice(), expected_stderr.to_owned()),
        "local settlement must return before loading the missing credentials with only the expected terminal output",
    );
}

#[test]
fn recover_missing_signing_seed_refuses_with_a_closed_event() {
    let dir = ScratchDir::new();
    let seed = dir.path().join("absent-signing-seed");
    let store = dir.path().join("absent-store");
    let pin = granary_net::config::render_tls_pin(&[1; 32]);
    let output = gran(
        &[
            "--log-format",
            "json",
            "--log-filter",
            "warn",
            "recover",
            store.to_str().unwrap(),
            "vol",
            "--writer",
            &"11".repeat(16),
            "--key-seed",
            seed.to_str().unwrap(),
            "--endpoint",
            "https://authority.invalid",
            "--pin",
            &pin,
            "--credential-context",
            "fixture",
        ],
        &[],
    );
    assert_eq!(
        (output.status.code(), output.stdout.is_empty()),
        (Some(1), true)
    );
    let stderr = text(&output.stderr);
    let event = "{\"level\":\"WARN\",\"target\":\"granary_client::event\",\"event\":\"recover.signing_key_refused\",\"spans\":[";
    let diagnostic = "gran recover: RecoverySigningKeyRefused: signing seed failed custody or could not be loaded";
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(event))
            .count(),
        1
    );
    assert_eq!(stderr.lines().filter(|line| *line == diagnostic).count(), 1);
    assert_eq!(stderr.lines().count(), 2);
    assert!(!seed.exists() && !store.exists());
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn input(dir: &ScratchDir) -> PathBuf {
    let path = dir.path().join("input.bin");
    fs::write(&path, vec![7_u8; 4096]).unwrap_or_else(|e| panic!("{e}"));
    path
}

fn config(dir: &ScratchDir, body: &str) -> PathBuf {
    let path = dir.path().join("log.conf");
    fs::write(&path, body).unwrap_or_else(|e| panic!("{e}"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| panic!("{e}"));
    path
}

/// `log.config` as the JSON stream and the text stream print it.
const JSON_CONFIG_STDERR: &str =
    "\"event\":\"log.config\",\"format\":\"json\",\"destination\":\"stderr\"";

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one nonempty binary matrix pairs every path source refusal with startup, exact exit/text and no output activation"
)]
fn paths_sources_pair_valid_startup_with_fixed_refusal_exit_and_no_activation() {
    let dir = ScratchDir::new();
    let input = input(&dir);
    let operand = input.to_str().unwrap();
    let log = dir.path().join("must-not-open.log");
    let log_operand = log.to_str().unwrap();
    let refuse = |run: Output, expected: &str| {
        assert!(run.status.code() == Some(2), "paths refusal exit changed");
        assert!(
            run.stderr == format!("gran: {expected}\n").as_bytes(),
            "paths refusal text changed or disclosed input"
        );
        assert!(
            run.stdout.is_empty() && !log.exists(),
            "refused paths source activated output or command"
        );
    };
    let mut cases = 0;
    for value in ["redacted", "full"] {
        let held = config(&dir, &format!("paths = {value}\n"));
        for run in [
            gran(&["--log-paths", value, "thresh", operand], &[]),
            gran(&["thresh", operand], &[("GRANARY_LOG_PATHS", value)]),
            gran(
                &["--log-config", held.to_str().unwrap(), "thresh", operand],
                &[],
            ),
        ] {
            assert!(
                run.status.success() && !run.stdout.is_empty(),
                "valid paths startup control failed"
            );
        }
    }
    for value in [
        "",
        "FULL",
        "Redacted",
        "full ",
        " full",
        "synthetic-invalid",
    ] {
        refuse(
            gran(
                &[
                    "--log-file",
                    log_operand,
                    "--log-paths",
                    value,
                    "thresh",
                    operand,
                ],
                &[],
            ),
            "log paths (flag): expected redacted or full",
        );
        refuse(
            gran(
                &[
                    "--log-file",
                    log_operand,
                    "--log-paths",
                    "redacted",
                    "thresh",
                    operand,
                ],
                &[("GRANARY_LOG_PATHS", value)],
            ),
            "log paths (environment): expected redacted or full",
        );
        cases += 2;
    }
    // The file grammar trims value whitespace; the other sources do not.
    for body in [
        "paths =\n",
        "paths = FULL\n",
        "paths = Redacted\n",
        "paths = synthetic-invalid\n",
        "paths full\n",
    ] {
        let held = config(&dir, body);
        refuse(
            gran(
                &[
                    "--log-file",
                    log_operand,
                    "--log-paths",
                    "redacted",
                    "--log-config",
                    held.to_str().unwrap(),
                    "thresh",
                    operand,
                ],
                &[],
            ),
            "log paths (configuration): expected redacted or full",
        );
        cases += 1;
    }
    let held = config(&dir, " paths = full \n");
    assert!(
        gran(
            &["--log-config", held.to_str().unwrap(), "thresh", operand],
            &[]
        )
        .status
        .success(),
        "valid held-file whitespace control failed"
    );
    for (body, expected) in [
        (
            "paths = full\npaths = redacted\n",
            "log paths (configuration): repeated key",
        ),
        (
            "synthetic-key = synthetic-value\n",
            "log configuration: unknown key",
        ),
    ] {
        let held = config(&dir, body);
        refuse(
            gran(
                &[
                    "--log-file",
                    log_operand,
                    "--log-config",
                    held.to_str().unwrap(),
                    "thresh",
                    operand,
                ],
                &[],
            ),
            expected,
        );
        cases += 1;
    }
    for (args, expected) in [
        (
            vec!["--log-file", log_operand, "--log-paths"],
            "log paths (flag): missing value",
        ),
        (
            vec![
                "--log-file",
                log_operand,
                "--log-paths",
                "--log-filter",
                "trace",
            ],
            "log paths (flag): missing value",
        ),
        (
            vec![
                "--log-file",
                log_operand,
                "--log-paths",
                "full",
                "--log-paths",
                "redacted",
            ],
            "log paths (flag): repeated option",
        ),
    ] {
        refuse(gran(&args, &[]), expected);
        cases += 1;
    }
    assert!(cases == 22, "configuration refusal inventory changed");
}

#[test]
fn non_unicode_paths_sources_refuse_without_opening_the_log() {
    use std::os::unix::ffi::OsStringExt as _;
    let dir = ScratchDir::new();
    let log = dir.path().join("must-not-open.log");
    for source in ["flag", "environment"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_gran"));
        for name in [
            "RUST_LOG",
            "GRANARY_LOG_FORMAT",
            "GRANARY_LOG_FILE",
            "GRANARY_LOG_FILTER",
            "GRANARY_LOG_CONFIG",
            "GRANARY_LOG_PATHS",
        ] {
            command.env_remove(name);
        }
        command.arg("--log-file").arg(&log);
        let value = std::ffi::OsString::from_vec(vec![0xff]);
        if source == "flag" {
            command.arg("--log-paths").arg(value);
        } else {
            command
                .env("GRANARY_LOG_PATHS", value)
                .args(["--log-paths", "redacted"]);
        }
        let run = command.output().unwrap();
        assert!(
            run.status.code() == Some(2) && run.stdout.is_empty() && !log.exists(),
            "non-Unicode paths source activated policy"
        );
        assert!(
            run.stderr
                == format!("gran: log paths ({source}): value is not valid UTF-8\n").as_bytes(),
            "non-Unicode paths refusal disclosed input"
        );
    }
}

#[test]
fn a_quiet_verb_writes_nothing_to_standard_error_under_the_default_filter() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let run = gran(&["thresh", file.to_str().unwrap_or_default()], &[]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    assert_eq!(
        text(&run.stderr),
        "",
        "the configuration event is DEBUG, so the default filter drops it"
    );
    assert!(!text(&run.stdout).is_empty());
}

#[test]
fn the_default_is_text_and_names_the_config_event_by_field() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let run = gran(
        &[
            "--log-filter",
            "debug",
            "thresh",
            file.to_str().unwrap_or_default(),
        ],
        &[],
    );
    assert!(run.status.success(), "{}", text(&run.stderr));
    let stderr = text(&run.stderr);
    for needle in [
        "event=\"log.config\"",
        "format=\"text\"",
        "destination=\"stderr\"",
        "kind=\"session\"",
        "op=\"cor-",
    ] {
        assert!(stderr.contains(needle), "missing {needle}: {stderr}");
    }
}

#[test]
fn the_flag_source_selects_json_and_a_file_and_refuses_a_malformed_value() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let input = file.to_str().unwrap_or_default();
    let log = dir.path().join("gran.log");
    let log_arg = log.to_str().unwrap_or_default();

    let valid = gran(
        &[
            "--log-format",
            "json",
            "--log-file",
            log_arg,
            "--log-filter",
            "debug",
            "thresh",
            input,
        ],
        &[],
    );
    assert!(valid.status.success(), "{}", text(&valid.stderr));
    assert_eq!(
        text(&valid.stderr),
        "",
        "a file destination leaves standard error empty"
    );
    let logged = fs::read_to_string(&log).unwrap_or_else(|e| panic!("{e}"));
    for needle in [
        "\"event\":\"log.config\"",
        "\"format\":\"json\"",
        "\"destination\":\"file\"",
        "\"kind\":\"session\"",
        "\"op\":\"cor-",
    ] {
        assert!(logged.contains(needle), "missing {needle}: {logged}");
    }
    assert!(
        logged
            .lines()
            .all(|l| l.starts_with('{') && l.ends_with('}')),
        "{logged}"
    );
    assert!(
        !text(&valid.stdout).is_empty(),
        "the command's own output is untouched"
    );

    let malformed = gran(&["--log-format", "xml", "thresh", input], &[]);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(
        text(&malformed.stderr)
            .contains("gran: --log-format: expected one of text, json; got \"xml\""),
        "{}",
        text(&malformed.stderr)
    );
    assert_eq!(text(&malformed.stdout), "", "a refused run does no work");
}

#[test]
fn the_environment_source_selects_json_and_refuses_a_malformed_value() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let input = file.to_str().unwrap_or_default();

    let valid = gran(
        &["thresh", input],
        &[
            ("GRANARY_LOG_FORMAT", "json"),
            ("GRANARY_LOG_FILTER", "debug"),
        ],
    );
    assert!(valid.status.success(), "{}", text(&valid.stderr));
    let stderr = text(&valid.stderr);
    assert!(stderr.contains(JSON_CONFIG_STDERR), "{stderr}");
    assert!(
        stderr
            .lines()
            .all(|l| l.starts_with('{') && l.ends_with('}')),
        "{stderr}"
    );

    let malformed = gran(&["thresh", input], &[("GRANARY_LOG_FORMAT", "xml")]);
    assert_eq!(malformed.status.code(), Some(2));
    assert!(
        text(&malformed.stderr)
            .contains("gran: GRANARY_LOG_FORMAT: expected one of text, json; got \"xml\""),
        "{}",
        text(&malformed.stderr)
    );

    let filter = gran(
        &["thresh", input],
        &[("GRANARY_LOG_FILTER", "granary_client=loud")],
    );
    assert_eq!(filter.status.code(), Some(2));
    assert!(
        text(&filter.stderr)
            .contains("GRANARY_LOG_FILTER: \"granary_client=loud\" was not understood"),
        "{}",
        text(&filter.stderr)
    );
}

#[test]
fn the_file_source_selects_json_and_refuses_a_malformed_value() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let input = file.to_str().unwrap_or_default();

    let valid = config(&dir, "# gran logging\nformat = json\nfilter = debug\n");
    let valid_arg = valid.to_str().unwrap_or_default();
    let run = gran(&["thresh", input], &[("GRANARY_LOG_CONFIG", valid_arg)]);
    assert!(run.status.success(), "{}", text(&run.stderr));
    assert!(
        text(&run.stderr).contains(JSON_CONFIG_STDERR),
        "{}",
        text(&run.stderr)
    );

    let malformed = config(&dir, "format = xml\n");
    let malformed_arg = malformed.to_str().unwrap_or_default();
    let run = gran(&["--log-config", malformed_arg, "thresh", input], &[]);
    assert_eq!(run.status.code(), Some(2));
    let want = format!("gran: {malformed_arg}: format: expected one of text, json; got \"xml\"");
    assert!(text(&run.stderr).contains(&want), "{}", text(&run.stderr));

    fs::set_permissions(&valid, fs::Permissions::from_mode(0o666))
        .unwrap_or_else(|e| panic!("{e}"));
    let run = gran(&["thresh", input], &[("GRANARY_LOG_CONFIG", valid_arg)]);
    assert_eq!(run.status.code(), Some(2));
    assert!(
        text(&run.stderr).contains("writable by group or other"),
        "{}",
        text(&run.stderr)
    );
}

#[test]
fn a_log_file_that_cannot_be_opened_stops_the_run_with_status_one() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let missing = dir.path().join("no-such-directory").join("gran.log");
    let run = gran(
        &[
            "--log-file",
            missing.to_str().unwrap_or_default(),
            "thresh",
            file.to_str().unwrap_or_default(),
        ],
        &[],
    );
    assert_eq!(run.status.code(), Some(1));
    assert!(
        text(&run.stderr).contains("gran: cannot open the log file"),
        "{}",
        text(&run.stderr)
    );
    assert_eq!(text(&run.stdout), "");
}

#[test]
fn an_unreadable_rust_log_runs_the_default_and_reports_the_event_by_name() {
    let dir = ScratchDir::new();
    let file = input(&dir);
    let run = gran(
        &[
            "--log-format",
            "json",
            "thresh",
            file.to_str().unwrap_or_default(),
        ],
        &[("RUST_LOG", "====")],
    );
    assert!(run.status.success(), "{}", text(&run.stderr));
    let stderr = text(&run.stderr);
    for needle in [
        "\"event\":\"log.filter_rejected\"",
        "\"source\":\"rust_log\"",
        "\"reason\":\"malformed\"",
        "\"level\":\"WARN\"",
    ] {
        assert!(stderr.contains(needle), "missing {needle}: {stderr}");
    }
}

/// Run `gran <args>` with standard error closed, as a supervisor that closed
/// descriptor 2 would. The Rust runtime reopens a closed descriptor 2 on
/// `/dev/null` before `main`, so the process still starts and its original
/// standard error is a working destination that discards.
fn gran_with_closed_stderr(args: &[&str]) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg("exec \"$0\" \"$@\" 2>&-")
        .arg(env!("CARGO_BIN_EXE_gran"))
        .args(args)
        .env("NO_COLOR", "1")
        .env_remove("RUST_LOG")
        .output()
        .unwrap_or_else(|e| panic!("gran did not run: {e}"))
}

#[test]
fn a_closed_standard_error_still_starts_and_keeps_telemetry_in_the_log_file() {
    let dir = ScratchDir::new();
    let operand = input(&dir);
    let log = dir.path().join("closed-stderr.log");
    let run = gran_with_closed_stderr(&[
        "--log-file",
        log.to_str().unwrap(),
        "--log-format",
        "json",
        "--log-filter",
        "debug",
        "thresh",
        operand.to_str().unwrap(),
    ]);
    assert!(
        run.status.success() && !run.stdout.is_empty(),
        "a closed standard error must not refuse the start: {:?}",
        text(&run.stderr)
    );
    let written = fs::read_to_string(&log).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        written.contains("\"event\":\"log.config\""),
        "telemetry must reach the file, and only telemetry: {written}"
    );
}
