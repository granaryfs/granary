// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local operator dispatch and whole-export refusals through the shipped binary.
#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test fixtures and assertions"
)]

#[path = "support_export/fixture.rs"]
mod fixture;
#[path = "process/output.rs"]
mod output;
mod process;
use output::CommandExt as _;

use fixture::{chmod, command, diagnostic, incarnation_text, outcome, pair, write_pair};
use granary_core::{
    authlog::{Envelope, Epoch, encode_envelope},
    debug_grant::Incarnation,
    support::{EntryStatus, ExportRefusal, SourceKind, SupportArchive, SupportLogMetadata},
};
use std::{path::PathBuf, process::Command};

struct Fixture {
    root: PathBuf,
    support: PathBuf,
    state: PathBuf,
    out: PathBuf,
}
impl Fixture {
    #[expect(
        clippy::disallowed_methods,
        reason = "process ID isolates test scratch paths"
    )]
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "granary-export-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        chmod(&root, 0o700);
        let support = root.join("support");
        let state = root.join("state");
        let out = root.join("archive");
        for dir in [&support, &state] {
            std::fs::create_dir(dir).unwrap();
            chmod(dir, 0o700);
        }
        let (_, config) = pair(&support);
        for volume in config.volumes.keys() {
            let path = state.join(format!("{}.log", volume.as_str()));
            std::fs::write(
                &path,
                encode_envelope(&Envelope::new(volume.clone(), Epoch::from_bytes([7; 16])))
                    .as_bytes(),
            )
            .unwrap();
            chmod(&path, 0o600);
        }
        Self {
            root,
            support,
            state,
            out,
        }
    }
    fn command(&self) -> Command {
        command(&self.support, &self.state, &self.out, true)
    }
    fn positive(&self) -> SupportArchive {
        let output = self.command().guarded_output().unwrap();
        outcome(&output, 0, "", true, &self.out);
        let archive = SupportArchive::decode(&std::fs::read(&self.out).unwrap())
            .unwrap_or_else(|e| panic!("{e}: {}", diagnostic(&output)));
        assert_eq!(
            (
                archive.members.len(),
                archive.members.contains_key(b"snapshot.bin".as_slice()),
                archive
                    .members
                    .contains_key(b"configuration.bin".as_slice())
            ),
            (6, true, true),
            "{}",
            diagnostic(&output)
        );
        let config = granary_core::support::SupportConfiguration::decode(
            &archive.members[b"configuration.bin".as_slice()],
        )
        .unwrap();
        for volume in config.volumes.keys() {
            let member = format!("{}.logmeta", volume.as_str()).into_bytes();
            let metadata = SupportLogMetadata::decode(&archive.members[&member])
                .unwrap_or_else(|e| panic!("{e}: {}", diagnostic(&output)));
            let source =
                std::fs::metadata(self.state.join(format!("{}.log", volume.as_str()))).unwrap();
            assert_eq!(
                (
                    metadata.volume,
                    metadata.envelope_version,
                    metadata.epoch,
                    metadata.size
                ),
                (volume.clone(), 1, Epoch::from_bytes([7; 16]), source.len()),
                "{}",
                diagnostic(&output)
            );
        }
        std::fs::remove_file(&self.out).unwrap();
        archive
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn support_export_incarnation_checks() {
    let fx = Fixture::new();
    let (snapshot, mut config) = pair(&fx.support);
    fx.positive();
    let token = incarnation_text(snapshot.incarnation);
    let output = fx
        .command()
        .args(["--incarnation", &token])
        .guarded_output()
        .unwrap();
    outcome(&output, 0, "", true, &fx.out);
    let archive = SupportArchive::decode(&std::fs::read(&fx.out).unwrap()).unwrap();
    assert_eq!(
        archive.manifest.expected_incarnation,
        Some(snapshot.incarnation),
        "{}",
        diagnostic(&output)
    );
    std::fs::remove_file(&fx.out).unwrap();
    config.incarnation = Incarnation::from_bytes([0xfe; 16]);
    write_pair(&fx.support, &snapshot, &config);
    let output = fx.command().guarded_output().unwrap();
    outcome(
        &output,
        65,
        "support-export refused: support incarnation disagreement\n",
        false,
        &fx.out,
    );
    config.incarnation = snapshot.incarnation;
    write_pair(&fx.support, &snapshot, &config);
    let output = fx
        .command()
        .args([
            "--incarnation",
            "incarnation:fefefefefefefefefefefefefefefefe",
        ])
        .guarded_output()
        .unwrap();
    outcome(
        &output,
        65,
        "support-export refused: support expected incarnation mismatch\n",
        false,
        &fx.out,
    );
    for malformed in [
        "fefefefefefefefefefefefefefefefe",
        "incarnation:FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE",
        "incarnation:00",
        "incarnation:gggggggggggggggggggggggggggggggg",
    ] {
        let output = fx
            .command()
            .args(["--incarnation", malformed])
            .guarded_output()
            .unwrap();
        assert_eq!(
            (
                output.status.code(),
                output.stdout.is_empty(),
                String::from_utf8_lossy(&output.stderr).starts_with("invalid incarnation"),
                fx.out.exists()
            ),
            (Some(64), true, true, false),
            "{}",
            diagnostic(&output)
        );
    }
}

#[test]
fn support_export_usage_and_help() {
    let fx = Fixture::new();
    fx.positive();
    let cases = [
        (vec!["support-export"], "missing support directory"),
        (vec!["support-export", "--unknown"], "unknown flag"),
        (vec!["support-export", "--support-dir"], "missing path"),
        (
            vec!["support-export", "--support-dir", "/support"],
            "missing state directory",
        ),
        (
            vec![
                "support-export",
                "--support-dir",
                "/support",
                "--state-dir",
                "/state",
            ],
            "missing output archive",
        ),
    ];
    assert!(!cases.is_empty());
    for (args, reason) in cases {
        let output = Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env_clear()
            .args(args)
            .guarded_output()
            .unwrap();
        assert_eq!(
            (
                output.status.code(),
                output.stdout.is_empty(),
                String::from_utf8_lossy(&output.stderr)
                    .starts_with(&format!("{reason}\nusage: granary-server support-export"))
            ),
            (Some(64), true, true),
            "{}",
            diagnostic(&output)
        );
    }
    for args in [vec!["--help"], vec!["support-export", "--help"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_granary-server"))
            .env_clear()
            .args(args)
            .guarded_output()
            .unwrap();
        assert_eq!(
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .contains("support-export --support-dir S --state-dir D --out A")
            ),
            (Some(64), true),
            "{}",
            diagnostic(&output)
        );
    }
}

#[test]
fn support_export_duplicate_flags() {
    let fx = Fixture::new();
    let archive = fx.positive();
    let token = incarnation_text(archive.manifest.incarnation);
    let cases: Vec<(Vec<std::ffi::OsString>, &str)> = vec![
        (
            vec!["--support-dir".into(), fx.support.as_os_str().to_owned()],
            "repeated flag",
        ),
        (
            vec![
                "--incarnation".into(),
                token.clone().into(),
                "--incarnation".into(),
                token.into(),
            ],
            "repeated incarnation",
        ),
        (
            vec!["--accept-unsupported-filesystem".into()],
            "repeated filesystem acknowledgement",
        ),
    ];
    assert_eq!(cases.len(), 3);
    for (args, reason) in cases {
        let output = fx.command().args(args).guarded_output().unwrap();
        assert_eq!(
            (
                output.status.code(),
                output.stdout.is_empty(),
                String::from_utf8_lossy(&output.stderr)
                    .starts_with(&format!("{reason}\nusage: granary-server support-export")),
                fx.out.exists()
            ),
            (Some(64), true, true, false),
            "{}",
            diagnostic(&output)
        );
    }
}

#[test]
fn support_export_absolute_paths() {
    let fx = Fixture::new();
    fx.positive();
    let relative = std::path::Path::new("relative");
    let cases = [
        (relative, fx.state.as_path(), fx.out.as_path()),
        (fx.support.as_path(), relative, fx.out.as_path()),
        (fx.support.as_path(), fx.state.as_path(), relative),
    ];
    assert_eq!(cases.len(), 3);
    for (support, state, out) in cases {
        let output = command(support, state, out, true).guarded_output().unwrap();
        assert_eq!(
            (
                output.status.code(),
                output.stdout.is_empty(),
                String::from_utf8_lossy(&output.stderr)
                    .starts_with("paths must be absolute\nusage: granary-server support-export"),
                fx.out.exists()
            ),
            (Some(64), true, true, false),
            "{}",
            diagnostic(&output)
        );
    }
}

#[test]
fn support_export_io_and_directory_refusal_reports() {
    let fx = Fixture::new();
    fx.positive();
    let output = command(
        &fx.root.join("SECRET-missing-directory"),
        &fx.state,
        &fx.out,
        true,
    )
    .guarded_output()
    .unwrap();
    outcome(
        &output,
        65,
        "support-export refused: directory missing\n",
        false,
        &fx.out,
    );
    chmod(&fx.support, 0o755);
    let output = fx.command().guarded_output().unwrap();
    outcome(
        &output,
        65,
        "support-export refused: directory protection\n",
        false,
        &fx.out,
    );
}

#[test]
fn support_export_unknown_and_planted_key_shipped() {
    let fx = Fixture::new();
    fx.positive();
    let sentinel = b"SECRET-PLANTED-KEY-AND-UNKNOWN-CONTENT";
    for path in [fx.support.join("unexpected"), fx.state.join("private.key")] {
        std::fs::write(path, sentinel).unwrap();
    }
    let output = fx.command().guarded_output().unwrap();
    outcome(&output, 0, "", true, &fx.out);
    let bytes = std::fs::read(&fx.out).unwrap();
    let archive = SupportArchive::decode(&bytes).unwrap();
    let refusals = archive
        .manifest
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                SourceKind::UnknownSupport | SourceKind::UnknownState
            ) && e.status == EntryStatus::Refused(ExportRefusal::NotAllowlisted)
        })
        .count();
    assert_eq!(
        (
            archive.members.len(),
            refusals,
            bytes.windows(sentinel.len()).any(|w| w == sentinel)
        ),
        (6, 2, false),
        "{}",
        diagnostic(&output)
    );
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux shipped file attack venue")]
fn support_export_linux_symlink_components_shipped() {
    let fx = Fixture::new();
    fx.positive();
    // Both the leaf and an ancestor resolve to a valid pair if followed.
    for (link, source) in [
        (fx.root.join("leaf-link"), fx.support.clone()),
        (fx.root.join("ancestor-link"), fx.root.clone()),
    ] {
        std::os::unix::fs::symlink(&source, &link).unwrap();
        let path = if source == fx.root {
            link.join("support")
        } else {
            link
        };
        let output = command(&path, &fx.state, &fx.out, true)
            .guarded_output()
            .unwrap();
        outcome(
            &output,
            65,
            "support-export refused: directory symlink or non-directory\n",
            false,
            &fx.out,
        );
    }
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "Linux shipped file attack venue")]
fn support_export_linux_oversize_sources_shipped() {
    let fx = Fixture::new();
    fx.positive();
    std::fs::OpenOptions::new()
        .write(true)
        .open(fx.support.join("SUPPORT-SNAPSHOT"))
        .unwrap()
        .set_len(8_388_609)
        .unwrap();
    let output = fx.command().guarded_output().unwrap();
    outcome(
        &output,
        65,
        "support-export refused: required SUPPORT-SNAPSHOT: oversize\n",
        false,
        &fx.out,
    );
}
