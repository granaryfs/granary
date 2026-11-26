// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;
use crate::tests::ScratchDir;
use granary_core::{
    sheaf::Timestamp,
    support::{
        BUNDLE_ARCHIVE_MAX, BUNDLE_MANIFEST_ENTRIES_MAX, BUNDLE_MANIFEST_MAX, BundleEntry,
        BundleEntryStatus, BundleKind, BundleRefusal, BundleVersion,
    },
};
use std::os::unix::{ffi::OsStrExt as _, fs::MetadataExt as _};
use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

struct Scratch {
    path: PathBuf,
    _directory: ScratchDir,
}

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = ScratchDir::new();
        std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = std::fs::canonicalize(&directory.0).unwrap();
        Self {
            path,
            _directory: directory,
        }
    }

    fn directory(&self, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = self.path.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn uid(&self) -> u32 {
        std::fs::symlink_metadata(&self.path).unwrap().uid()
    }
}

fn version() -> BundleVersion {
    BundleVersion {
        package_major: 1,
        package_minor: 2,
        package_patch: 3,
        prerelease: false,
        target_os: 3,
        target_arch: 3,
        debug_assertions: true,
        features: 0,
        metrics_schema: 2,
        cache_marker_version: 1,
        cache_index_version: 1,
        overlay_journal_version: 1,
    }
}

fn offline_args(
    output: PathBuf,
    cache: Declaration,
    overlay: Declaration,
    store: Declaration,
    mountpoint: MountDeclaration,
) -> Args {
    Args {
        output,
        mode: Mode::Offline {
            cache,
            overlay,
            store,
            mountpoint,
        },
    }
}

#[test]
fn offline_mount_gone_exports_writer_version_and_six_explicit_statuses() {
    let archive =
        offline_archive(Timestamp { secs: 9, nanos: 10 }, version(), false, true).unwrap();
    assert_eq!(archive.manifest.entries.len(), BUNDLE_MANIFEST_ENTRIES_MAX);
    assert!(matches!(
        archive.manifest.entries[0].status,
        BundleEntryStatus::Exported { .. }
    ));
    let statuses = archive
        .manifest
        .entries
        .iter()
        .skip(1)
        .map(|entry| (entry.kind, entry.status))
        .collect::<Vec<_>>();
    assert_eq!(
        statuses,
        vec![
            (
                BundleKind::Configuration,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
            (
                BundleKind::Logs,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
            (
                BundleKind::Overlay,
                BundleEntryStatus::Refused(BundleRefusal::NotApplicable),
            ),
            (
                BundleKind::Cache,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
            (
                BundleKind::Failures,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
            (
                BundleKind::Metrics,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
        ]
    );
    assert_eq!(
        granary_core::support::BundleArchive::decode(&archive.encode().unwrap()).unwrap(),
        archive
    );
    assert_eq!(archive.manifest.encode().unwrap().len(), 182);
    assert_eq!(archive.encode().unwrap().len(), 281);
}

#[test]
fn publication_exit_codes_distinguish_refusal_and_uncertainty() {
    assert_eq!(publication_result(Ok(())), ExitCode::SUCCESS);
    assert_eq!(
        publication_result(Err(granary_client::PrivateArchiveError::Refused(
            granary_client::PrivateArchiveRefusal::InvalidOutputPath,
        ))),
        ExitCode::from(1)
    );
    assert_eq!(
        publication_result(Err(
            granary_client::PrivateArchiveError::PublicationUncertain,
        )),
        ExitCode::from(3)
    );
}

fn os(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn support_arguments_accept_complete_live_and_offline_forms() {
    let offline = parse(&os(&[
        "--output",
        "/private/bundle.gsb",
        "--offline",
        "--cache-dir",
        "none",
        "--overlay-dir",
        "none",
        "--store-dir",
        "none",
        "--mountpoint",
        "unknown",
    ]))
    .unwrap();
    assert_eq!(offline.output, PathBuf::from("/private/bundle.gsb"));
    assert_eq!(
        parse(&os(&["/mnt", "--output", "/private/live.gsb"]))
            .unwrap()
            .mode,
        Mode::Live(PathBuf::from("/mnt"))
    );
}

#[test]
fn support_arguments_require_one_complete_live_or_offline_form() {
    let refused = [
        os(&[
            "/mnt",
            "--output",
            "/private/bundle.gsb",
            "--offline",
            "--cache-dir",
            "none",
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            "unknown",
        ]),
        os(&[
            "--output",
            "/private/bundle.gsb",
            "--offline",
            "--cache-dir",
            "none",
            "--overlay-dir",
            "none",
            "--mountpoint",
            "unknown",
        ]),
        os(&[
            "--output",
            "/private/bundle.gsb",
            "--offline",
            "--cache-dir",
            "/cache",
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            "unknown",
        ]),
        os(&[
            "--output",
            "/private/first.gsb",
            "--output",
            "/private/second.gsb",
            "--offline",
            "--cache-dir",
            "none",
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            "unknown",
        ]),
        os(&[
            "--output",
            "/private/bundle.gsb",
            "--offline",
            "--offline",
            "--cache-dir",
            "none",
            "--overlay-dir",
            "none",
            "--store-dir",
            "none",
            "--mountpoint",
            "unknown",
        ]),
        os(&["-h"]),
    ];
    let errors = refused
        .iter()
        .map(|args| parse(args).unwrap_err())
        .collect::<Vec<_>>();
    assert_eq!(
        errors,
        [
            "live target cannot be combined with --offline",
            "--store-dir is required with --offline",
            "unknown mountpoint cannot be mixed with a source path",
            "--output repeated option",
            "--offline repeated option",
            "unknown option",
        ]
    );
    assert_eq!(errors.len(), 6);
}

#[test]
fn assembly_caps_refuse_before_destination_allocation() {
    let mut cases = 0;
    for kind in [
        BundleKind::Version,
        BundleKind::Configuration,
        BundleKind::Logs,
        BundleKind::Overlay,
        BundleKind::Cache,
        BundleKind::Failures,
        BundleKind::Metrics,
    ] {
        let produced = std::cell::Cell::new(false);
        let mut entries = Vec::new();
        let mut members = BTreeMap::new();
        assert!(
            add(
                kind,
                Ok((kind.cap(), || {
                    produced.set(true);
                    Ok(vec![0; kind.cap()])
                })),
                &mut entries,
                &mut members,
            )
            .is_ok()
        );
        assert!(produced.replace(false));
        assert_eq!(
            add(
                kind,
                Ok((kind.cap() + 1, || {
                    produced.set(true);
                    Ok(Vec::new())
                })),
                &mut entries,
                &mut members,
            ),
            Err("support size bound")
        );
        assert!(!produced.get(), "{kind:?} produced bytes past its cap");
        cases += 1;
    }
    for cap in [BUNDLE_MANIFEST_MAX, BUNDLE_ARCHIVE_MAX] {
        let allocated = std::cell::Cell::new(None);
        assert!(bounded_allocation(cap, cap, |length| allocated.set(Some(length))).is_ok());
        assert_eq!(allocated.replace(None), Some(cap));
        assert_eq!(
            bounded_allocation(cap + 1, cap, |length| allocated.set(Some(length))),
            Err("support size bound")
        );
        assert_eq!(allocated.get(), None, "whole object reserved past {cap}");
        cases += 1;
    }

    let entries = [
        BundleKind::Version,
        BundleKind::Configuration,
        BundleKind::Logs,
        BundleKind::Overlay,
        BundleKind::Cache,
        BundleKind::Failures,
        BundleKind::Metrics,
    ]
    .map(|kind| BundleEntry {
        kind,
        status: BundleEntryStatus::Refused(BundleRefusal::Unavailable),
    });
    let mut members = BTreeMap::new();
    members.insert(BundleKind::Logs, vec![0; BUNDLE_ARCHIVE_MAX]);
    let allocated = std::cell::Cell::new(false);
    assert_eq!(
        preflight_with(&entries, &members, |_| allocated.set(true)),
        Err("support size bound")
    );
    assert!(!allocated.get(), "archive allocation preceded preflight");
    assert_eq!(cases, 9);
}

#[test]
fn declared_mountpoint_identity_and_device_reach_offline_custody() {
    let scratch = Scratch::new();
    let missing = scratch.path.join("missing-mountpoint");
    assert_eq!(
        offline_mount(&missing),
        Err("source separation unavailable")
    );

    let ordinary = scratch.directory("ordinary-mountpoint");
    let (_, ordinary_device) = offline_mount(&ordinary).unwrap();
    assert_eq!(ordinary_device, None);

    let parent = PathBuf::from("/");
    let mounted = PathBuf::from("/dev");
    let parent_dev = std::fs::symlink_metadata(&parent).unwrap().dev();
    let mounted_dev = std::fs::symlink_metadata(&mounted).unwrap().dev();
    assert_ne!(
        mounted_dev, parent_dev,
        "distinct-device mount premise: parent={parent_dev}, mounted={mounted_dev}"
    );
    let (_, device) = offline_mount(&mounted).unwrap();
    assert_eq!(device, Some(mounted_dev));

    let output = scratch.directory("device-output").join("bundle.gsb");
    let args = offline_args(
        output.clone(),
        Declaration::None,
        Declaration::None,
        Declaration::None,
        MountDeclaration::Path(mounted),
    );
    let observed = std::cell::Cell::new(None);
    let exit = invoke_offline_with_mount(&args, scratch.uid(), |path, identity, device| {
        observed.set(Some(device));
        granary_client::MountedNamespace::new(path, identity, device)
    });
    assert_eq!(
        (exit, observed.get(), output.is_file()),
        (ExitCode::SUCCESS, Some(Some(mounted_dev)), true)
    );
}

#[test]
fn declared_mountpoint_walk_refuses_symlinked_components() {
    let scratch = Scratch::new();
    let real = scratch.directory("mountpoint-real");
    let nested = real.join("x");
    let mountpoint = nested.join("mp");
    std::fs::create_dir(&nested).unwrap();
    std::fs::create_dir(&mountpoint).unwrap();

    let ancestor_link = scratch.path.join("mountpoint-link");
    std::os::unix::fs::symlink(&real, &ancestor_link).unwrap();
    let parent_link = scratch.path.join("mountpoint-parent-link");
    std::os::unix::fs::symlink(&nested, &parent_link).unwrap();

    assert_eq!(offline_mount(&mountpoint).unwrap().1, None);
    assert_eq!(
        offline_mount(&ancestor_link.join("x/mp")),
        Err("source separation unavailable")
    );
    assert_eq!(
        offline_mount(&parent_link.join("mp")),
        Err("source separation unavailable")
    );
}

#[test]
fn swapped_live_source_refuses_before_archive_temporary() {
    let scratch = Scratch::new();
    let root = scratch.directory("live-source");
    let output_parent = scratch.directory("live-output");
    let (identity, _) = granary_client::prove_mountpoint(&root).unwrap();
    let sources = vec![granary_core::support_trigger::SourceRoot {
        role: granary_core::support_trigger::RootRole::Cache,
        path: root.as_os_str().as_bytes().to_vec(),
        dev: identity.0,
        ino: identity.1,
    }];
    let archive =
        offline_archive(Timestamp { secs: 1, nanos: 2 }, version(), false, false).unwrap();
    let layout = granary_core::support_trigger::SourceLayout {
        mount: granary_core::support_trigger::MountState::Absent,
        roots: sources,
    };
    std::fs::rename(&root, scratch.path.join("old-live-source")).unwrap();
    std::fs::create_dir(&root).unwrap();
    let output = output_parent.join("bundle.gsb");
    let target = scratch.path.join("mount");
    let args = Args {
        output: output.clone(),
        mode: Mode::Live(target.clone()),
    };
    let reasons = std::cell::RefCell::new(Vec::new());
    assert_eq!(
        (
            invoke_live_with(
                &args,
                scratch.uid(),
                || Ok((target.clone(), layout, archive)),
                |reason| reasons.borrow_mut().push(reason.to_owned()),
            ),
            reasons.into_inner(),
            std::fs::read_dir(&output_parent).unwrap().count(),
        ),
        (
            ExitCode::FAILURE,
            vec!["source separation unavailable".to_owned()],
            0,
        ),
        "swapped root was accepted or created an archive temporary"
    );
}

#[test]
fn mounted_roots_beneath_the_resolved_target_are_not_walked() {
    let target = PathBuf::from("/resolved/mount");
    let beneath = target.join("cache");
    let source = granary_core::support_trigger::SourceRoot {
        role: granary_core::support_trigger::RootRole::Cache,
        path: beneath.as_os_str().as_bytes().to_vec(),
        dev: u64::MAX,
        ino: u64::MAX,
    };
    assert!(
        prove_live_roots(Some(&target), std::slice::from_ref(&source))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        prove_live_roots(None, &[source]),
        Err("source separation unavailable")
    );

    let unresolved = granary_core::support_trigger::SourceRoot {
        role: granary_core::support_trigger::RootRole::Cache,
        path: b"/resolved/mount/../outside".to_vec(),
        dev: u64::MAX,
        ino: u64::MAX,
    };
    assert_eq!(
        prove_live_roots(Some(&target), &[unresolved]),
        Err("source separation unavailable")
    );
}

#[test]
fn live_request_failure_never_publishes_or_falls_back_offline() {
    let scratch = Scratch::new();
    let output_parent = scratch.directory("live-request-output");
    let target = scratch.directory("covered-target");
    let archive =
        offline_archive(Timestamp { secs: 1, nanos: 2 }, version(), false, false).unwrap();
    let layout = granary_core::support_trigger::SourceLayout {
        mount: granary_core::support_trigger::MountState::Absent,
        roots: Vec::new(),
    };
    let valid_output = output_parent.join("valid.gsb");
    let valid = Args {
        output: valid_output.clone(),
        mode: Mode::Live(target.clone()),
    };
    assert_eq!(
        invoke_live_with(
            &valid,
            scratch.uid(),
            || Ok((target.clone(), layout.clone(), archive.clone())),
            |_| {},
        ),
        ExitCode::SUCCESS
    );

    let mut cases = 0;
    for (name, failure) in [
        (
            "unavailable.gsb",
            crate::attach::SupportRequestFailure::Unavailable,
        ),
        (
            "malformed.gsb",
            crate::attach::SupportRequestFailure::Malformed,
        ),
    ] {
        let output = output_parent.join(name);
        let args = Args {
            output: output.clone(),
            mode: Mode::Live(target.clone()),
        };
        let reasons = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            (
                invoke_live_with(
                    &args,
                    scratch.uid(),
                    || Err(failure),
                    |reason| reasons.borrow_mut().push(reason.to_owned()),
                ),
                output.exists(),
                reasons.into_inner(),
            ),
            (
                ExitCode::FAILURE,
                false,
                vec![
                    match failure {
                        crate::attach::SupportRequestFailure::Unavailable => {
                            "support producer unavailable"
                        }
                        crate::attach::SupportRequestFailure::Malformed =>
                            "malformed support reply",
                    }
                    .to_owned()
                ],
            ),
            "failure={failure:?}"
        );
        cases += 1;
    }
    assert_eq!(
        (
            cases,
            std::fs::read_dir(output_parent).unwrap().count(),
            valid_output.is_file(),
        ),
        (2, 1, true),
        "a failed live request created a final or temporary archive"
    );
}

#[test]
fn declared_overlay_and_cache_paths_reach_their_own_statuses() {
    let scratch = Scratch::new();
    let output_parent = scratch.directory("status-output");
    let mountpoint = scratch.directory("status-mountpoint");
    let overlay = scratch.directory("status-overlay");
    let cache = scratch.directory("status-cache");
    let publish = |name, cache, overlay| {
        let output = output_parent.join(name);
        let args = offline_args(
            output.clone(),
            cache,
            overlay,
            Declaration::None,
            MountDeclaration::Path(mountpoint.clone()),
        );
        assert_eq!(invoke_offline(&args, scratch.uid()), ExitCode::SUCCESS);
        BundleArchive::decode(&std::fs::read(output).unwrap()).unwrap()
    };
    let statuses = |archive: &BundleArchive| {
        archive
            .manifest
            .entries
            .iter()
            .filter(|entry| matches!(entry.kind, BundleKind::Overlay | BundleKind::Cache))
            .map(|entry| (entry.kind, entry.status))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        statuses(&publish(
            "overlay.gsb",
            Declaration::None,
            Declaration::Path(overlay),
        )),
        [
            (
                BundleKind::Overlay,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
            (
                BundleKind::Cache,
                BundleEntryStatus::Refused(BundleRefusal::NotApplicable),
            ),
        ]
    );
    assert_eq!(
        statuses(&publish(
            "cache.gsb",
            Declaration::Path(cache),
            Declaration::None,
        )),
        [
            (
                BundleKind::Overlay,
                BundleEntryStatus::Refused(BundleRefusal::NotApplicable),
            ),
            (
                BundleKind::Cache,
                BundleEntryStatus::Refused(BundleRefusal::Unavailable),
            ),
        ]
    );
}

#[test]
fn offline_existing_mountpoint_publishes_and_missing_refuses_before_temporary() {
    let scratch = Scratch::new();
    let output_parent = scratch.directory("output");
    let mountpoint = scratch.directory("mountpoint");
    let valid_output = output_parent.join("valid.gsb");
    let mut args = offline_args(
        valid_output.clone(),
        Declaration::None,
        Declaration::None,
        Declaration::None,
        MountDeclaration::Path(mountpoint),
    );
    assert_eq!(invoke_offline(&args, scratch.uid()), ExitCode::SUCCESS);
    assert!(valid_output.is_file());

    let refused_output = output_parent.join("missing.gsb");
    args.output = refused_output.clone();
    let Mode::Offline { mountpoint, .. } = &mut args.mode else {
        panic!("offline fixture")
    };
    *mountpoint = MountDeclaration::Path(scratch.path.join("missing-mountpoint"));
    assert_eq!(invoke_offline(&args, scratch.uid()), ExitCode::FAILURE);
    assert!(!refused_output.exists());
    assert!(
        std::fs::read_dir(&output_parent)
            .unwrap()
            .all(|entry| entry.unwrap().file_name() == "valid.gsb"),
        "missing mountpoint created an archive temporary"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn offline_cli_custody_publishes_or_refuses_source_nesting() {
    let scratch = Scratch::new();
    let output_parent = scratch.directory("output");
    let source = scratch.directory("source");
    let mountpoint = scratch.directory("mountpoint");
    let valid_output = output_parent.join("valid.gsb");
    let valid = offline_args(
        valid_output.clone(),
        Declaration::None,
        Declaration::None,
        Declaration::None,
        MountDeclaration::Path(mountpoint.clone()),
    );
    assert_eq!(invoke_offline(&valid, scratch.uid()), ExitCode::SUCCESS);
    assert!(valid_output.is_file());

    let refused_output = source.join("refused.gsb");
    let refused = offline_args(
        refused_output.clone(),
        Declaration::Path(source.clone()),
        Declaration::None,
        Declaration::None,
        MountDeclaration::Path(mountpoint),
    );
    assert_eq!(invoke_offline(&refused, scratch.uid()), ExitCode::FAILURE);
    assert!(!refused_output.exists());
    assert_eq!(
        2,
        usize::from(valid_output.is_file()) + usize::from(!refused_output.exists())
    );
}
