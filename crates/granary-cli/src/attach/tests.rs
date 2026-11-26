// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: Apache-2.0

//! Unit tests for `crate::attach` — mount parsing, preflight, coordination,
//! detachment verification, and mount help.
//!
//! Out-of-line, at the sibling-directory path
//! `attach/tests.rs`: the parent keeps its path
//! and declares `#[cfg(test)] mod tests;`.
//!
//! The two `cmd_mount_gran` rows and the `usage_text` row stay with their
//! subjects in the crate root. `MountScratchDir` has no production dependency;
//! it lives with the attachment rows and is re-exported for the dispatch row.
#![cfg(test)]
#![expect(
    clippy::disallowed_methods,
    reason = "test module: fixtures use bare fs calls on their own scratch directories; disallowed_methods has no allow-in-tests knob"
)]

use super::*;

use crate::tests::{a_pin, osstr, pause, root_key_str, vol};
use crate::usage;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

#[test]
fn construction_workspace_mount_flag_has_checked_writable_policy() {
    let key = root_key_str();
    let mut cases = 0;
    for (value, expected) in [
        ("1024", 1_073_741_824),
        ("2048", 2_147_483_648),
        ("16384", 17_179_869_184),
    ] {
        let args = parse_mount(&mount_argv(&[
            "--writable",
            "--root-key",
            &key,
            "--construction-workspace-mib",
            value,
        ]))
        .unwrap();
        assert_eq!(args.construction_workspace_bytes, expected);
        cases += 1;
    }
    for value in ["1023", "16385"] {
        let error = parse_mount(&mount_argv(&[
            "--writable",
            "--root-key",
            &key,
            "--construction-workspace-mib",
            value,
        ]))
        .err();
        assert_eq!(
            error.as_deref(),
            Some("--construction-workspace-mib must be between 1024 and 16384 MiB")
        );
        cases += 1;
    }
    for value in ["bad", "18446744073709551616"] {
        let error = parse_mount(&mount_argv(&[
            "--writable",
            "--root-key",
            &key,
            "--construction-workspace-mib",
            value,
        ]))
        .err();
        assert_eq!(
            error,
            Some(format!(
                "--construction-workspace-mib: {value:?} is not a u32"
            ))
        );
        cases += 1;
    }
    assert_eq!(
        parse_mount(&mount_argv(&[
            "--root-key",
            &key,
            "--construction-workspace-mib",
            "1024"
        ]))
        .err()
        .as_deref(),
        Some("writable operands require --writable")
    );
    assert_eq!(
        parse_mount(&mount_argv(&["--writable", "--root-key", &key]))
            .unwrap()
            .construction_workspace_bytes,
        1_073_741_824
    );
    assert_eq!(cases, 7);
}

#[test]
fn overlay_cap_mount_flag_is_runtime_only_and_checked() {
    let key = root_key_str();
    let parse = |value: Option<&str>| {
        let mut operands = vec!["--writable", "--root-key", key.as_str()];
        if let Some(value) = value {
            operands.extend(["--overlay-cap-bytes", value]);
        }
        parse_mount(&mount_argv(&operands))
    };
    let configured = parse(Some("268435456")).unwrap();
    let later_default = parse(None).unwrap();
    let minimum = parse(Some("44938292")).unwrap();
    let below = parse(Some("44938291")).err().unwrap();
    assert_eq!(
        (
            configured.overlay_cap_bytes,
            later_default.overlay_cap_bytes,
            minimum.overlay_cap_bytes,
            below.as_str(),
        ),
        (
            268_435_456,
            134_217_728,
            44_938_292,
            "--overlay-cap-bytes must be at least 44938292 bytes",
        )
    );
}

#[cfg(feature = "overlay-fault-tests")]
mod bounded_unmount;

#[test]
fn control_start_reports_resolution_refusal() {
    let mut cases = 0;
    for available in [true, false] {
        let target = if available {
            DetachTarget::Resolved(PathBuf::from("/mount"))
        } else {
            DetachTarget::Unavailable(VerifyRefusal::io("parent lookup refused".into()))
        };
        let starts = std::cell::Cell::new(0);
        let mut lines = Vec::new();
        let control = start_control(
            &target,
            |path| {
                assert_eq!(path, Path::new("/mount"));
                starts.set(starts.get() + 1);
                Ok(7)
            },
            |line| lines.push(line.to_string()),
        );
        assert_eq!(
            (control, starts.get(), lines),
            if available {
                (Some(7), 1, vec![])
            } else {
                (
                    None,
                    0,
                    vec![
                        "gran mount: control endpoint unavailable: parent lookup refused"
                            .to_owned(),
                    ],
                )
            }
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn support_start_reports_a_fixed_fatal_refusal() {
    let resolved = DetachTarget::Resolved(PathBuf::from("/mount"));
    let unavailable = DetachTarget::Unavailable(VerifyRefusal::io("path detail".into()));
    let mut cases = 0;

    for target in [&unavailable, &resolved] {
        let mut lines = Vec::new();
        let result = start_support(
            target,
            |_| Err::<u8, _>(std::io::Error::other("injected detail")),
            |line| lines.push(line.to_string()),
        );
        assert_eq!(
            (result, lines),
            (
                None,
                vec!["gran mount: support producer unavailable".to_owned()]
            )
        );
        cases += 1;
    }

    let mut lines = Vec::new();
    assert_eq!(
        start_support(&resolved, |_| Ok(9), |line| lines.push(line.to_string())),
        Some(9)
    );
    assert!(lines.is_empty());
    cases += 1;
    assert_eq!(cases, 3);
}

#[test]
fn support_reply_mount_state_must_match_the_requesters_mountinfo() {
    let scratch = MountScratchDir::new();
    let target = scratch.0.join("mount");
    let key = granary_core::mount_control::MountKey {
        namespace_dev: 1,
        namespace_ino: 2,
        mount_id: 3,
        fuse_major: 4,
        fuse_minor: 5,
    };
    let row = mount_table::ControlMount { key, owner: 6 };
    let mounted = granary_core::support_trigger::MountState::Mounted {
        mountpoint: (7, 8),
        key,
    };
    let absent = granary_core::support_trigger::MountState::Absent;
    let archive = crate::support_bundle::offline_archive(
        granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        crate::support_bundle::writer_version().unwrap(),
        false,
        false,
    )
    .unwrap();
    let cases = [
        (mounted, vec![row], Ok(())),
        (absent, Vec::new(), Ok(())),
        (mounted, Vec::new(), Err(SupportRequestFailure::Malformed)),
        (absent, vec![row], Err(SupportRequestFailure::Malformed)),
    ];
    let observed = cases
        .into_iter()
        .map(|(header, rows, expected)| {
            let result = request_support_bundle_with(
                &target,
                6,
                |_| {
                    Ok((
                        granary_core::support_trigger::SourceLayout {
                            mount: header,
                            roots: Vec::new(),
                        },
                        archive.clone(),
                    ))
                },
                |_| Ok(rows.clone()),
            )
            .map(|_| ());
            assert_eq!(result, expected, "header={header:?}, rows={rows:?}");
            result
        })
        .count();
    assert_eq!(observed, 4);
}

#[test]
fn support_request_resolution_and_mountinfo_failures_use_the_live_contract() {
    use std::os::unix::fs::symlink;

    let scratch = MountScratchDir::new();
    let real_parent = scratch.0.join("real");
    std::fs::create_dir(&real_parent).unwrap();
    let linked_parent = scratch.0.join("linked");
    symlink(&real_parent, &linked_parent).unwrap();
    let expected = real_parent.join("mount");
    let resolved_expected = std::fs::canonicalize(&real_parent).unwrap().join("mount");
    let archive = crate::support_bundle::offline_archive(
        granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        crate::support_bundle::writer_version().unwrap(),
        false,
        false,
    )
    .unwrap();
    let layout = granary_core::support_trigger::SourceLayout {
        mount: granary_core::support_trigger::MountState::Absent,
        roots: Vec::new(),
    };
    let current = std::env::current_dir().unwrap();
    let mut relative = PathBuf::new();
    for _ in current.components().skip(1) {
        relative.push("..");
    }
    relative.push(expected.strip_prefix("/").unwrap());
    let trailing = PathBuf::from(format!("{}/", expected.display()));
    let symlinked = linked_parent.join("mount");
    let mut cases = 0;
    for spelling in [&expected, &relative, &trailing, &symlinked] {
        let requested = std::cell::RefCell::new(None);
        let observed = std::cell::RefCell::new(None);
        let (resolved, _, _) = request_support_bundle_with(
            spelling,
            6,
            |path| {
                requested.replace(Some(path.to_path_buf()));
                Ok((layout.clone(), archive.clone()))
            },
            |path| {
                observed.replace(Some(path.to_path_buf()));
                Ok(Vec::new())
            },
        )
        .unwrap();
        assert_eq!(
            (resolved, requested.into_inner(), observed.into_inner(),),
            (
                resolved_expected.clone(),
                Some(resolved_expected.clone()),
                Some(resolved_expected.clone()),
            ),
            "spelling={spelling:?}"
        );
        cases += 1;
    }
    assert_eq!(cases, 4);

    assert_eq!(
        request_support_bundle_with(
            &expected,
            6,
            |_| Ok((layout, archive)),
            |_| Err(std::io::Error::other("injected mountinfo failure")),
        )
        .unwrap_err(),
        SupportRequestFailure::Unavailable
    );
}

#[test]
fn control_mount_capture_keeps_refusal_detail() {
    let mount = mount_table::ControlMount {
        key: granary_core::mount_control::MountKey {
            namespace_dev: 1,
            namespace_ino: 2,
            mount_id: 3,
            fuse_major: 0,
            fuse_minor: 4,
        },
        owner: 5,
    };
    let mut cases = 0;
    for reason in [
        None,
        Some("refusing: the target carries a mount that is not granary's"),
        Some("refusing: missing, duplicate or malformed FUSE user_id"),
        Some("refusing: mountinfo exceeded its read bound"),
    ] {
        let observed =
            reason.map_or_else(|| Ok(vec![mount]), |why| Err(std::io::Error::other(why)));
        let mut lines = Vec::new();
        let key = control_mount_key(observed, 5, |line| lines.push(line.to_string()));
        assert_eq!(
            (key, lines),
            reason.map_or_else(
                || (Some(mount.key), vec![]),
                |why| (
                    None,
                    vec![format!(
                        "gran mount: control mount identity/owner capture failed: {why}"
                    )]
                )
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn control_service_errors_are_reported_without_stopping_mount() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "attach::tests::control_service_error_notice_child",
            "--nocapture",
        ])
        .env("GRANARY_TEST_CONTROL_NOTICE", "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert_eq!(
        (
            output.status.success(),
            stderr
                .matches("control service failed (InvalidInput)")
                .count(),
            stderr
                .matches("control accept failed (Interrupted); retrying")
                .count()
        ),
        (true, 3, 1),
        "child stderr={stderr}"
    );
    assert_eq!(
        stderr
            .matches("the mount and signal path remain available")
            .count(),
        3
    );
}

#[test]
fn control_mount_capture_refuses_ambiguous_rows() {
    let mount = mount_table::ControlMount {
        key: granary_core::mount_control::MountKey {
            namespace_dev: 1,
            namespace_ino: 2,
            mount_id: 3,
            fuse_major: 0,
            fuse_minor: 4,
        },
        owner: 5,
    };
    let mut cases = 0;
    for (mounts, reason) in [
        (vec![mount], None),
        (
            vec![],
            Some("expected exactly one granary FUSE row, found 0"),
        ),
        (
            vec![mount, mount],
            Some("expected exactly one granary FUSE row, found 2"),
        ),
        (
            vec![mount_table::ControlMount { owner: 6, ..mount }],
            Some("kernel FUSE owner 6 differs from admitted owner 5"),
        ),
    ] {
        let mut lines = Vec::new();
        let key = control_mount_key(Ok(mounts), 5, |line| lines.push(line.to_string()));
        assert_eq!(
            (key, lines),
            reason.map_or_else(
                || (Some(mount.key), vec![]),
                |reason| (
                    None,
                    vec![format!(
                        "gran mount: control mount identity/owner capture failed: {reason}"
                    )]
                )
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn control_service_error_notice_child() {
    if std::env::var_os("GRANARY_TEST_CONTROL_NOTICE").is_none() {
        return;
    }
    let fatal = Exit::ControlError {
        kind: std::io::ErrorKind::InvalidInput,
        fatal: true,
    };
    let (send, receive) = std::sync::mpsc::channel();
    for event in [
        fatal,
        Exit::ControlError {
            kind: std::io::ErrorKind::Interrupted,
            fatal: false,
        },
        Exit::ControlUmount,
        fatal,
        Exit::Outcome(granary_client::ShutdownReport::lost()),
        fatal,
        Exit::SessionEnded,
    ] {
        send.send(event).unwrap();
    }
    let starts = std::cell::Cell::new(0);
    let expires = std::cell::Cell::new(0);
    let result = run_coordinator(
        &receive,
        None,
        Some(EngineStop {
            start: |_| {
                starts.set(starts.get() + 1);
                Ok(())
            },
            expire: || expires.set(expires.get() + 1),
        }),
        || Ok(()),
        || panic!("unexpected fallback detach"),
        || 7,
        std::time::Duration::from_secs(5),
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (
            result.arm,
            result.joined,
            starts.get(),
            expires.get(),
            receive.try_iter().count()
        ),
        (Exit::ControlUmount, Some(7), 1, 0, 0)
    );
}

#[test]
fn shutdown_fenced_status_preserves_counts() {
    let mut cases = 0;
    for (residue, counts) in [
        (
            Some(granary_client::Residue {
                files: 3,
                bytes: 912,
                operations: 5,
            }),
            "3 files (912 bytes) unsynced, 5 operations uncommitted",
        ),
        (None, "what was left could not be read"),
    ] {
        let report = granary_client::ShutdownReport {
            outcome: granary_client::ShutdownOutcome::Fenced,
            cut: None,
            residue,
            elapsed_ms: 12,
        };
        assert_eq!(
            mount_status_line(
                "gran umount",
                Some((Some(report), Path::new("store"))),
                MountOutcome::Fenced
            ),
            format!(
                "gran umount: shutdown fenced after 12 ms: {counts}; the authority refused this mount's ownership or its commit; the overlay is kept in store: preserve it; recovery is explicit; daemon fenced (exit 5)"
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

#[test]
fn shutdown_unknown_cut_is_not_invented() {
    let report = granary_client::ShutdownReport {
        outcome: granary_client::ShutdownOutcome::Incomplete(
            granary_client::ShutdownCause::Deadline,
        ),
        cut: None,
        residue: None,
        elapsed_ms: 12,
    };
    let line =
        shutdown_status_line("gran mount", Some((Some(report), Path::new("store")))).unwrap();
    assert!(
        line.contains("shutdown stopped; the cut was not recorded"),
        "status: {line}"
    );
}

#[test]
fn control_subscription_does_not_reset_grace() {
    let (send, receive) = std::sync::mpsc::channel();
    for _ in 0..11 {
        send.send(Exit::ControlUmount).unwrap();
    }
    let ticks = std::cell::Cell::new(0_u32);
    let start = granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime);
    let coordinated = run_coordinator(
        &receive,
        None,
        None::<NoEngine>,
        || Ok(()),
        || Ok(()),
        || (),
        std::time::Duration::from_millis(50),
        || {
            let tick = ticks.get();
            ticks.set(tick + 1);
            start + std::time::Duration::from_millis(u64::from(tick) * 10)
        },
    );
    assert_eq!(
        (
            coordinated.joined.is_none(),
            ticks.get(),
            receive.try_iter().count()
        ),
        (true, 6, 6)
    );
}

#[test]
fn control_signal_orders() {
    let mut cases = 0;
    for (events, expected_trigger, expected_expiry) in [
        (
            vec![
                Exit::ControlUmount,
                Exit::Signal("SIGTERM"),
                Exit::ControlUmount,
            ],
            Some(granary_client::ShutdownTrigger::Umount),
            1,
        ),
        (
            vec![Exit::Signal("SIGTERM"), Exit::ControlUmount],
            Some(granary_client::ShutdownTrigger::Signal),
            0,
        ),
        (
            vec![Exit::Teardown, Exit::ControlUmount, Exit::Signal("SIGTERM")],
            Some(granary_client::ShutdownTrigger::Umount),
            1,
        ),
        (vec![Exit::SessionEnded, Exit::ControlUmount], None, 0),
    ] {
        let (send, receive) = std::sync::mpsc::channel();
        for event in events {
            send.send(event).unwrap();
        }
        let trigger = std::cell::Cell::new(None);
        let expiry = std::cell::Cell::new(0);
        let begins = std::cell::Cell::new(0);
        let coordinated = run_coordinator(
            &receive,
            None,
            Some(EngineStop {
                start: |started| {
                    trigger.set(Some(started));
                    begins.set(begins.get() + 1);
                    send.send(Exit::Outcome(committed())).unwrap();
                    Ok(())
                },
                expire: || expiry.set(expiry.get() + 1),
            }),
            || {
                send.send(Exit::SessionEnded).unwrap();
                Ok(())
            },
            || Ok(()),
            || (),
            SHORT_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        assert_eq!(
            (
                trigger.get(),
                begins.get(),
                expiry.get(),
                coordinated.report,
                coordinated.joined.is_some()
            ),
            (
                expected_trigger,
                usize::from(expected_trigger.is_some()),
                expected_expiry,
                expected_trigger.map(|_| committed()),
                true
            )
        );
        cases += 1;
    }
    assert_eq!(cases, 4);
}

#[test]
fn control_fallback_never_retargets_after_stop() {
    let mut cases = 0;
    for absent_before_stop in [true, false] {
        for detach in [MountOutcome::Clean, MountOutcome::RuntimeFailure] {
            let attempts = std::cell::Cell::new(0);
            let detaches = std::cell::Cell::new(0);
            let lines = std::cell::RefCell::new(Vec::new());
            let outcome = owner_umount(
                || {
                    attempts.set(attempts.get() + 1);
                    Err(control::Failure { absent_before_stop })
                },
                || {
                    detaches.set(detaches.get() + 1);
                    detach
                },
                &|line| lines.borrow_mut().push(line.to_owned()),
            );
            let expected = if absent_before_stop && detach == MountOutcome::Clean {
                vec!["gran umount: detached; shutdown outcome unavailable".to_owned()]
            } else {
                Vec::new()
            };
            assert_eq!(
                (outcome, attempts.get(), detaches.get(), lines.into_inner()),
                (
                    MountOutcome::RuntimeFailure,
                    1,
                    usize::from(absent_before_stop),
                    expected
                )
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4);
}

// ============================================================
// gran mount: parse
// ============================================================

// ---------------------------------------------- Step 1: parse_mount

#[test]
fn mount_helper_keeps_writable_operands_unknown() {
    let key = root_key_str();
    let common = format!(
        "endpoint=https://h,pin={},root_key={key},foreground",
        a_pin()
    );
    let mut cases = 0;
    for unsupported in ["writable", "key_seed=synthetic-seed", "view=strict"] {
        let accepted =
            parse_mount_gran(&[osstr("vol"), osstr("/mnt"), osstr("-o"), osstr(&common)]).unwrap();
        assert_eq!(
            (
                accepted.trust_server,
                accepted.manifest_root,
                accepted.allow_other,
                accepted.seq
            ),
            (false, None, false, None)
        );
        let refused = parse_mount_gran(&[
            osstr("vol"),
            osstr("/mnt"),
            osstr("-o"),
            osstr(&format!("{common},{unsupported}")),
        ])
        .unwrap_err();
        assert!(
            refused.contains("unknown"),
            "unknown helper operand: {refused}"
        );
        assert!(refused.contains(unsupported.split('=').next().unwrap()));
        cases += 1;
    }
    assert_eq!(cases, 3);
}

#[test]
fn mount_view_option_is_writable_only_and_strict_only() {
    let key = root_key_str();
    let default =
        parse_mount(&mount_argv(&["--writable", "--root-key", &key])).map(|args| args.view);
    let strict = parse_mount(&mount_argv(&[
        "--writable",
        "--view",
        "strict",
        "--root-key",
        &key,
    ]))
    .map(|args| args.view);
    let read_only = parse_mount(&mount_argv(&["--view", "strict", "--root-key", &key])).err();
    let read_only_after = parse_mount(&mount_argv(&[
        "--view",
        "strict",
        "--writable",
        "--root-key",
        &key,
    ]))
    .map(|args| args.view);
    let loose = parse_mount(&mount_argv(&[
        "--writable",
        "--view",
        "loose",
        "--root-key",
        &key,
    ]))
    .err();
    let helper = parse_mount_gran(&[
        osstr("vol"),
        osstr("/mnt"),
        osstr("-o"),
        osstr(&format!(
            "endpoint=https://h,pin={},root_key={key},foreground,view=strict",
            a_pin()
        )),
    ])
    .err();
    assert_eq!(
        (
            default,
            strict,
            read_only.as_deref(),
            read_only_after,
            loose.as_deref(),
            helper
                .as_deref()
                .is_some_and(|err| err.contains("unknown") && err.contains("view")),
            MOUNT_HELP.contains("--view strict:"),
        ),
        (
            Ok(granary_client::ViewMode::Default),
            Ok(granary_client::ViewMode::Strict),
            Some("writable operands require --writable"),
            Ok(granary_client::ViewMode::Strict),
            Some("--view: \"loose\" is not \"strict\""),
            true,
            true,
        )
    );
}

/// `--shutdown-bound` is writable-only, defaults to thirty seconds, and
/// takes 1 to 3600 seconds through the checked parser; zero, past an hour,
/// or not a number is a usage error, and so is the flag without
/// `--writable`.
#[test]
fn shutdown_bound_flag() {
    let key = root_key_str();
    let bound = |extra: &[&str]| {
        let mut argv = vec!["--writable", "--root-key", key.as_str()];
        argv.extend_from_slice(extra);
        parse_mount(&mount_argv(&argv)).map(|args| args.shutdown_bound)
    };
    let read_only = parse_mount(&mount_argv(&["--shutdown-bound", "10", "--root-key", &key])).err();
    assert_eq!(
        (
            bound(&[]),
            bound(&["--shutdown-bound", "1"]),
            bound(&["--shutdown-bound", "3600"]),
            bound(&["--shutdown-bound", "0"]),
            bound(&["--shutdown-bound", "3601"]),
            bound(&["--shutdown-bound", "x"]),
            read_only.as_deref(),
        ),
        (
            Ok(30),
            Ok(1),
            Ok(3600),
            Err("--shutdown-bound: 0 is not between 1 and 3600 seconds".to_owned()),
            Err("--shutdown-bound: 3601 is not between 1 and 3600 seconds".to_owned()),
            Err("--shutdown-bound: \"x\" is not a u32".to_owned()),
            Some("writable operands require --writable"),
        )
    );
}

/// `vol /mnt --endpoint https://h --pin <a_pin>`, plus whatever the
/// caller adds — mirrors `publish_argv`'s own shape. Callers still
/// need to add a trust-mode flag: `parse_mount` requires one, and a
/// shared baseline that already picked one would hide tests of the
/// exclusivity rule itself.
fn mount_argv(extra: &[&str]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = ["vol", "/mnt", "--endpoint", "https://h", "--pin"]
        .iter()
        .map(|s| osstr(s))
        .collect();
    argv.push(osstr(&a_pin()));
    argv.extend(extra.iter().map(|s| osstr(s)));
    argv
}

/// The same trio, again, on `gran mount`.
#[test]
fn mount_parses_the_wire_snapshot_trio_when_all_three_are_given() {
    let parsed = parse_mount(&mount_argv(&[
        "--trust-server",
        "--wire-snapshot",
        "/tmp/snap.json",
        "--wire-run-id",
        "run-1",
        "--wire-role",
        "client-1",
    ]))
    .unwrap_or_else(|e| panic!("{e}"));
    let wire = parsed.wire.expect("all three given");
    assert_eq!(wire.path, PathBuf::from("/tmp/snap.json"));
    assert_eq!(wire.run_id, "run-1");
    assert_eq!(wire.role, "client-1");
}

/// A PARTIAL trio is refused on `gran mount` too.
#[test]
fn mount_refuses_a_partial_wire_snapshot_trio() {
    let err = parse_mount(&mount_argv(&[
        "--trust-server",
        "--wire-snapshot",
        "/tmp/snap.json",
    ]))
    .expect_err("path given, run-id and role absent");
    assert!(
        err.contains("--wire-run-id") && err.contains("--wire-role"),
        "got: {err}"
    );
}

/// **An invalid wire-role VALUE must be refused on
/// `gran mount` — the exact motivating case.** `gran
/// mount --wire-role clientt-1` (note the typo) must
/// be refused before mounting anything, not just at
/// unmount when the snapshot is finally written.
#[test]
fn mount_refuses_a_bad_role_value_before_doing_any_work() {
    let err = parse_mount(&mount_argv(&[
        "--trust-server",
        "--wire-snapshot",
        "/tmp/snap.json",
        "--wire-run-id",
        "run-1",
        "--wire-role",
        "clientt-1",
    ]))
    .expect_err("clientt-1 is not in the closed role vocabulary");
    assert!(
        err.contains("vocabulary"),
        "the refusal must be traceable to SnapshotError::UnknownRole specifically \
         (its Display text is the only one of the four value-refusal variants that \
         contains \"vocabulary\"), not merely to SOME value error, got: {err}"
    );
}

#[test]
fn parse_mount_happy_path_with_root_key() {
    let key = root_key_str();
    let args = mount_argv(&[
        "--root-key",
        &key,
        "--cache-dir",
        "/c",
        "--seq",
        "5",
        "--uid",
        "1000",
        "--gid",
        "1000",
    ]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.volume, vol("vol"));
    assert_eq!(parsed.mountpoint, PathBuf::from("/mnt"));
    assert_eq!(parsed.endpoint, "https://h");
    assert_eq!(parsed.tls_pins.len(), 1);
    assert!(parsed.root_key.is_some(), "root_key must be populated");
    assert!(parsed.manifest_root.is_none());
    assert!(!parsed.trust_server);
    assert_eq!(parsed.cache_dir, Some(PathBuf::from("/c")));
    assert_eq!(parsed.seq, Some(5));
    assert_eq!(parsed.uid, Some(1000));
    assert_eq!(parsed.gid, Some(1000));
    assert!(!parsed.allow_other);
    assert!(!parsed.foreground);
    assert!(!parsed.reset_floor);
    assert!(!parsed.force);
}

#[test]
fn parse_mount_manifest_root_parses_a_grain_id() {
    let id = GrainId::of(b"parse-mount-manifest-root-test");
    let args = mount_argv(&["--manifest-root", &id.to_string()]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.manifest_root, Some(id));
    assert!(parsed.root_key.is_none());
    assert!(!parsed.trust_server);
}

#[test]
fn parse_mount_trust_server_is_valueless() {
    let args = mount_argv(&["--trust-server"]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.trust_server);
}

#[test]
fn parse_mount_support_bundle_is_a_valueless_opt_in() {
    let default = parse_mount(&mount_argv(&["--trust-server"])).unwrap();
    let parsed = parse_mount(&mount_argv(&[
        "--trust-server",
        "--support-bundle",
        "--foreground",
    ]))
    .unwrap();
    assert_eq!(
        (
            default.support_bundle,
            parsed.support_bundle,
            parsed.foreground
        ),
        (false, true, true)
    );
    assert!(
        MOUNT_HELP.contains("[--support-bundle]"),
        "the opt-in must be advertised in gran mount help"
    );
}

/// THE quirk the brief names. `parse_cat` (this crate's other
/// hand-rolled parser with no valueless flag) makes EVERY
/// `--`-prefixed token consume the next argument; `gran mount` has
/// six valueless flags exercised here, each special-cased BEFORE the
/// value-taking branch or a flag placed right before `--endpoint`
/// silently eats it. This row was run against the parser without that
/// special-casing, and failed.
#[test]
fn parse_mount_valueless_flags_do_not_eat_the_next_argument() {
    let key = root_key_str();
    // Every valueless flag in this row is placed before a value-taking
    // one, in one invocation: if any of the six were NOT
    // special-cased, its neighbour's value would be swallowed and
    // either a required field would come back `None`/empty or the
    // positional count would come out wrong.
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "--trust-server",
        "--allow-other",
        "--foreground",
        "--reset-floor",
        "--force",
        "--support-bundle",
        "--endpoint",
        "https://h",
        "--pin",
    ]
    .iter()
    .map(|s| osstr(s))
    .chain(std::iter::once(osstr(&a_pin())))
    .collect();
    let _ = key; // trust-server is the mode; root-key unused here
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.trust_server);
    assert!(parsed.allow_other);
    assert!(parsed.foreground);
    assert!(parsed.reset_floor);
    assert!(parsed.force);
    assert!(parsed.support_bundle);
    assert_eq!(
        parsed.endpoint, "https://h",
        "a swallowed --endpoint is the exact failure mode the ordering guards against"
    );
    assert_eq!(
        parsed.tls_pins.len(),
        1,
        "--pin's value must not have been eaten either"
    );
}

#[test]
fn parse_mount_requires_a_trust_mode() {
    let args = mount_argv(&[]);
    let err = parse_mount(&args).expect_err("no trust mode must be refused");
    assert!(
        err.contains("--root-key")
            && err.contains("--manifest-root")
            && err.contains("--trust-server"),
        "the refusal must name all three options, got: {err}"
    );
}

#[test]
fn parse_mount_refuses_two_trust_modes_at_once() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--trust-server"]);
    let err = parse_mount(&args).expect_err("two trust modes must be refused");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn parse_mount_refuses_three_trust_modes_at_once() {
    let key = root_key_str();
    let id = GrainId::of(b"parse-mount-three-trust-modes");
    let args = mount_argv(&[
        "--root-key",
        &key,
        "--manifest-root",
        &id.to_string(),
        "--trust-server",
    ]);
    let err = parse_mount(&args).expect_err("three trust modes must be refused");
    assert!(err.contains("exactly one"), "got: {err}");
}

#[test]
fn parse_mount_pin_is_required() {
    let key = root_key_str();
    let args: Vec<OsString> = ["vol", "/mnt", "--endpoint", "https://h", "--root-key", &key]
        .iter()
        .map(|s| osstr(s))
        .collect();
    let err = parse_mount(&args).expect_err("no --pin must be refused");
    assert!(err.contains("--pin"), "got: {err}");
}

#[test]
fn parse_mount_reuses_parse_cat_seq_and_refuses_the_two_reserved_seqs() {
    let key = root_key_str();
    let zero = mount_argv(&["--root-key", &key, "--seq", "0"]);
    let err0 = parse_mount(&zero).expect_err("seq 0 must be refused");
    let cat_err0 = parse_cat_seq("0").expect_err("parse_cat_seq must refuse seq 0 too");
    assert_eq!(
        err0, cat_err0,
        "identical error text is the proof parse_mount calls parse_cat_seq rather than a \
         second parser that could drift from it"
    );

    let max = mount_argv(&["--root-key", &key, "--seq", &u64::MAX.to_string()]);
    let err_max = parse_mount(&max).expect_err("u64::MAX must be refused");
    let cat_err_max =
        parse_cat_seq(&u64::MAX.to_string()).expect_err("parse_cat_seq must refuse u64::MAX too");
    assert_eq!(err_max, cat_err_max);
}

#[test]
fn parse_mount_reset_floor_and_force_parse_independently() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--reset-floor"]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.reset_floor);
    assert!(!parsed.force, "--reset-floor must not also set --force");

    let args = mount_argv(&["--root-key", &key, "--force"]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.force);
    assert!(
        !parsed.reset_floor,
        "--force must not also set --reset-floor"
    );
}

#[test]
fn parse_mount_uid_gid_reject_non_numeric() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--uid", "not-a-number"]);
    let err = parse_mount(&args).expect_err("a non-numeric --uid must be refused");
    assert!(err.contains("--uid"), "got: {err}");
}

#[test]
fn parse_mount_unknown_flag_refused() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--not-a-real-flag", "x"]);
    let err = parse_mount(&args).expect_err("an unknown flag must be refused");
    assert!(err.contains("--not-a-real-flag"), "got: {err}");
}

// ------------------------------- Explicit --breakage flag arming

#[cfg(feature = "conformance-breakage")]
#[test]
fn parse_mount_breakage_accepts_a_known_variant() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--breakage", "follow-symlink"]);
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.breakage, Some(granary_fuse::Breakage::FollowSymlink));
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn parse_mount_breakage_refuses_an_unknown_variant_naming_the_accepted_set() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--breakage", "not-a-real-variant"]);
    let err = parse_mount(&args).expect_err("an unknown --breakage value must be refused");
    assert!(err.contains("not-a-real-variant"), "got: {err}");
    assert!(
        err.contains("follow-symlink"),
        "the refusal must name the accepted set, got: {err}"
    );
}

// `parse_mount` PARSES `--breakage` into
// `MountArgs.breakage`; it must NOT refuse on absence (that moved to
// `mount_attempt_with_credentials` — see
// `mount_attempt_with_credentials_refuses_missing_breakage_before_set_id_and_regardless_of_entry_point`
// below, immediately before the Item-2 tests).
#[cfg(feature = "conformance-breakage")]
#[test]
fn parse_mount_leaves_breakage_none_and_does_not_refuse_when_absent() {
    let key = root_key_str();
    let mut args: Vec<OsString> = ["vol", "/mnt", "--endpoint", "https://h", "--pin"]
        .iter()
        .map(|s| osstr(s))
        .collect();
    args.push(osstr(&a_pin()));
    args.push(osstr("--root-key"));
    args.push(osstr(&key));
    let parsed = parse_mount(&args).unwrap_or_else(|e| panic!("parse_mount must not refuse: {e}"));
    assert_eq!(parsed.breakage, None);
}

// fact 1 (already true, no new mechanism): a NORMAL (non-feature)
// build's `other => Err(...)` arm already refuses `--breakage` as an
// unknown flag; feature builds instead require explicit arming. This
// pins that, it does not add anything.
#[cfg(not(feature = "conformance-breakage"))]
#[test]
fn parse_mount_breakage_flag_is_unknown_on_a_normal_build() {
    let key = root_key_str();
    let args = mount_argv(&["--root-key", &key, "--breakage", "x"]);
    let err = parse_mount(&args).expect_err("--breakage must be refused on a non-feature build");
    assert!(err.contains("unknown flag --breakage"), "got: {err}");
}

#[cfg(feature = "conformance-breakage")]
#[test]
fn breakage_banner_formats_the_exact_grepped_string() {
    assert_eq!(
        breakage_banner("follow-symlink"),
        "BREAKAGE ACTIVE: follow-symlink"
    );
}

#[test]
fn breakage_banner_reaches_the_protected_sink_with_logging_off() {
    struct Buffer(std::sync::mpsc::Sender<Vec<u8>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .send(bytes.to_vec())
                .expect("buffer receiver is held");
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let (tx, rx) = std::sync::mpsc::channel();
    let (sink, mut worker) = crate::sink::sink_to_writer(Buffer(tx));
    let mut log = sink.writer(crate::sink::Stream::Protected);
    let subscriber = granary_client::closed_subscriber(
        granary_client::LogFormat::Text,
        tracing_subscriber::EnvFilter::new("off"),
        sink.clone(),
    );
    tracing::subscriber::with_default(subscriber, || {
        emit_breakage_banner("follow-symlink", &mut log);
    });
    // Observe delivery with the writer still alive and without a flush.
    let delivered = rx.recv_timeout(std::time::Duration::from_secs(2));
    worker.close();
    assert_eq!(
        delivered.as_deref(),
        Ok(b"BREAKAGE ACTIVE: follow-symlink\n".as_slice()),
        "the banner must reach the protected sink even with logging off"
    );
}

#[test]
fn parse_mount_wrong_positional_count_refused() {
    let err = parse_mount(&[osstr("only-one")]).expect_err("one positional must be refused");
    assert!(err.contains("expected 2 positional"), "got: {err}");
}

// --------------------------------------------- Step 1: parse_umount

#[test]
fn parse_umount_happy_path() {
    let parsed = parse_umount(&[osstr("/mnt")]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed, PathBuf::from("/mnt"));
}

#[test]
fn parse_umount_refuses_any_flag() {
    let err = parse_umount(&[osstr("/mnt"), osstr("--force")]).expect_err("umount takes no flags");
    assert!(err.contains("--force"), "got: {err}");
}

#[test]
fn parse_umount_refuses_wrong_positional_count() {
    let err = parse_umount(&[]).expect_err("zero positionals must be refused");
    assert!(err.contains("expected 1 positional"), "got: {err}");
}

// ---------------------------------------------- Step 2: argv[0] dispatch

#[test]
fn invoked_as_mount_gran_matches_the_file_name_only() {
    assert!(invoked_as_mount_gran(OsStr::new("/sbin/mount.gran")));
    assert!(invoked_as_mount_gran(OsStr::new("mount.gran")));
    assert!(invoked_as_mount_gran(OsStr::new("./mount.gran")));
    assert!(!invoked_as_mount_gran(OsStr::new("/usr/local/bin/gran")));
    assert!(!invoked_as_mount_gran(OsStr::new("mount.gran2")));
    assert!(!invoked_as_mount_gran(OsStr::new("gmount.gran/gran")));
}

#[test]
fn parse_mount_gran_argv_parses_device_dir_and_repeated_o() {
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        "root_key=ed25519:aa,endpoint=https://h",
        "-o",
        "allow_other,pin=sha256/xx",
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let parsed = parse_mount_gran_argv(&args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(parsed.device, osstr("vol"));
    assert_eq!(parsed.dir, osstr("/mnt"));
    assert_eq!(
        parsed.options,
        vec![
            ("root_key".to_owned(), Some("ed25519:aa".to_owned())),
            ("endpoint".to_owned(), Some("https://h".to_owned())),
            ("allow_other".to_owned(), None),
            ("pin".to_owned(), Some("sha256/xx".to_owned())),
        ],
        "two -o occurrences must ACCUMULATE, matching mount(8) itself"
    );
}

#[test]
fn parse_mount_gran_argv_dangling_o_refused() {
    let err = parse_mount_gran_argv(&[osstr("vol"), osstr("/mnt"), osstr("-o")])
        .expect_err("a dangling -o must be refused");
    assert!(err.contains("-o needs a value"), "got: {err}");
}

/// The translation itself, checked field-by-field against a native
/// invocation carrying the equivalent flags — the property under
/// test is that the two produce the SAME `MountArgs`, not merely
/// that `parse_mount_gran` returns `Ok`.
#[test]
fn parse_mount_gran_translates_the_o_list_to_native_flags() {
    let key = root_key_str();
    let native_args: Vec<OsString> = [
        "vol",
        "/mnt",
        "--endpoint",
        "https://h",
        "--pin",
        &a_pin(),
        "--root-key",
        &key,
        "--seq",
        "9",
        "--uid",
        "7",
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let native = parse_mount(&native_args).unwrap_or_else(|e| panic!("{e}"));

    let mount_gran_args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!(
            "endpoint=https://h,pin={},root_key={key},seq=9,uid=7",
            a_pin()
        ),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let translated = parse_mount_gran(&mount_gran_args).unwrap_or_else(|e| panic!("{e}"));

    assert_eq!(translated.volume, native.volume);
    assert_eq!(translated.mountpoint, native.mountpoint);
    assert_eq!(translated.endpoint, native.endpoint);
    assert_eq!(translated.tls_pins, native.tls_pins);
    assert_eq!(translated.root_key, native.root_key);
    assert_eq!(translated.seq, native.seq);
    assert_eq!(translated.uid, native.uid);
    // Neither invocation here arms `breakage`: the native one omits
    // `--breakage`, and the `-o breakage=` vocabulary was
    // REVERTED — see `parse_mount_gran`'s own doc. The
    // equivalence this test proves must hold on the new field too:
    // both are unarmed, and it is `mount_attempt_with_credentials`,
    // not either parser, that refuses that later.
    #[cfg(feature = "conformance-breakage")]
    {
        assert_eq!(native.breakage, None);
        assert_eq!(translated.breakage, None);
    }
}

#[test]
fn parse_mount_gran_valueless_o_options_translate() {
    let key = root_key_str();
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!(
            "endpoint=https://h,pin={},root_key={key},allow_other,foreground,reset_floor,force",
            a_pin()
        ),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let parsed = parse_mount_gran(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.allow_other);
    assert!(parsed.foreground);
    assert!(parsed.reset_floor);
    assert!(parsed.force);
}

/// A machine-wide entry point requires `--root-key`. This
/// is the property [`parse_mount`] does NOT enforce on its own —
/// `--trust-server` alone is a perfectly valid native mount — so the
/// refusal has to be proven at the `mount.gran` layer specifically.
#[test]
fn parse_mount_gran_refuses_trust_server() {
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!("endpoint=https://h,pin={},trust_server", a_pin()),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let err = parse_mount_gran(&args).expect_err("mount.gran must refuse --trust-server");
    assert!(
        err.contains("--trust-server") && err.contains("--root-key"),
        "got: {err}"
    );
}

#[test]
fn parse_mount_gran_refuses_manifest_root() {
    let id = GrainId::of(b"parse-mount-gran-refuses-manifest-root");
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!("endpoint=https://h,pin={},manifest_root={id}", a_pin()),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let err = parse_mount_gran(&args).expect_err("mount.gran must refuse --manifest-root");
    assert!(
        err.contains("--manifest-root") && err.contains("--root-key"),
        "got: {err}"
    );
}

#[test]
fn parse_mount_gran_accepts_root_key() {
    let key = root_key_str();
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!("endpoint=https://h,pin={},root_key={key}", a_pin()),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let parsed = parse_mount_gran(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(parsed.root_key.is_some());
}

#[test]
fn parse_mount_gran_unknown_o_key_refused() {
    let args: Vec<OsString> = ["vol", "/mnt", "-o", "not_a_real_option=x"]
        .iter()
        .map(|s| osstr(s))
        .collect();
    let err = parse_mount_gran(&args).expect_err("an unknown -o key must be refused");
    assert!(err.contains("not_a_real_option"), "got: {err}");
}

/// The rule "do not re-add the `-o breakage=`
/// vocabulary" was prose with no gate — a
/// re-added arm would pass 804/804, because the equivalence test
/// pins `breakage: None` on both sides without ever SUPPLYING the
/// option. This test does supply it, on BOTH builds (not cfg'd to
/// the feature at all, deliberately: the refusal reason differs —
/// feature-off, `granary_fuse::Breakage` does not exist so the key
/// can only ever be unknown; feature-on, the key must STILL be
/// unknown even though the TYPE exists, because the one and
/// only arming vocabulary is `gran mount --breakage <name>`, never
/// an `-o` option a real fstab line could reach unsupervised — see
/// `mount_attempt_with_credentials`'s own doc on why that path was
/// rejected).
#[test]
fn parse_mount_gran_never_accepts_a_breakage_o_key() {
    // An OTHERWISE-VALID invocation (root_key + endpoint + pin) so
    // that a re-added vocabulary would flip this to Ok — not to a
    // DIFFERENT Err (e.g. a missing --pin) that could pass this
    // test's own assertion for the wrong reason.
    let key = root_key_str();
    let args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!(
            "endpoint=https://h,pin={},root_key={key},breakage=truncate-read",
            a_pin()
        ),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let err = parse_mount_gran(&args)
        .expect_err("mount.gran must refuse a breakage= option on every build");
    // The refusal must identify the rejected `-o` key: a
    // bare `err.contains("breakage")` passes for the WRONG reason
    // on a feature-OFF build if the vocabulary were ever re-added —
    // a re-added `-o breakage=` arm that translates to `--breakage`
    // would make `parse_mount` answer `unknown flag --breakage`,
    // which ALSO contains "breakage", so the substring check cannot
    // tell "mount.gran refused the -o KEY" apart from "mount.gran
    // accepted the key and parse_mount refused the translated FLAG
    // instead" — the exact failure mode this test exists to catch.
    // Assert the SHAPE `parse_mount_gran` itself produces for an
    // unknown `-o` option instead (`(other, _) => Err(format!(
    // "mount.gran: unknown -o option {other}"))`), which the two
    // failure modes cannot both produce.
    assert_eq!(
        err, "mount.gran: unknown -o option breakage",
        "the refusal must be mount.gran's OWN \"unknown -o option\" shape, not merely \
         contain the word \"breakage\" somewhere (which a re-added vocabulary that \
         translates to --breakage would ALSO produce, via parse_mount's \"unknown flag\" \
         message, on a feature-off build) — got: {err}"
    );
}

#[test]
fn parse_mount_gran_value_shape_mismatches_are_named() {
    // A valueless option given a value.
    let args: Vec<OsString> = ["vol", "/mnt", "-o", "allow_other=yes"]
        .iter()
        .map(|s| osstr(s))
        .collect();
    let err = parse_mount_gran(&args).expect_err("allow_other takes no value");
    assert!(
        err.contains("allow_other") && err.contains("no value"),
        "got: {err}"
    );

    // A value-required option given none.
    let args: Vec<OsString> = ["vol", "/mnt", "-o", "endpoint"]
        .iter()
        .map(|s| osstr(s))
        .collect();
    let err = parse_mount_gran(&args).expect_err("endpoint needs a value");
    assert!(
        err.contains("endpoint") && err.contains("needs a value"),
        "got: {err}"
    );
}

// -------------------------------------------------- Step 3: pre-flight

/// A fixture matching every other scratch-dir test in this file:
/// pid + a per-process counter, so two tests in one binary never
/// collide.
pub(crate) struct MountScratchDir(pub(crate) PathBuf);
impl MountScratchDir {
    pub(crate) fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        // Matches this file's own `ScratchDir::new` precedent exactly:
        // the wholesale `mod tests` licence above covers the FS rows
        // (create_dir_all below), but `std::process::id` is a
        // DIFFERENT, non-fs row of the same lint (ambient process input)
        // and needs its own narrow reason rather than riding on the
        // fs-labelled wholesale one.
        #[expect(
            clippy::disallowed_methods,
            reason = "the lint row this licenses bans `std::process::id` as AMBIENT INPUT, because \
                      the preimage of a hashed or signed value must take a `WriterIdentity` \
                      instead. Here it is a SCRATCH-DIRECTORY NAME and nothing else \
                      (`granary-mount-preflight-test-<pid>-<counter>` under the temp dir, \
                      created and removed by this fixture); the counter beside it is \
                      per-process, so without the pid two concurrent test runs would generate \
                      the same name and share one directory. It reaches no hashed or signed \
                      value, and nothing under test reads it"
        )]
        let dir = std::env::temp_dir().join(format!(
            "granary-mount-preflight-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
        Self(dir)
    }
}
impl Drop for MountScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The pre-flight's error contract, pinned directly: EACH refusal names the
/// condition it found, in words an operator can act on, and every
/// variant is exercised here — including `AlreadyMounted`, which no
/// OTHER test on this box constructs (its only production producer,
/// `refuse_if_already_mounted`'s Linux arm, does not compile here).
#[test]
fn mount_preflight_error_display_names_every_condition() {
    let p = PathBuf::from("/mnt/x");
    let cases: Vec<(MountPreflightError, &str)> = vec![
        (
            MountPreflightError::NotFound(p.clone()),
            "no such directory",
        ),
        (
            MountPreflightError::NotADirectory(p.clone()),
            "not a directory",
        ),
        (MountPreflightError::Symlink(p.clone()), "symlink"),
        (
            MountPreflightError::AlreadyMounted(p.clone()),
            "already a mount point",
        ),
        (MountPreflightError::NotEmpty(p.clone()), "not empty"),
        (
            MountPreflightError::MountCheckUnsupported { os: "plan9" },
            "plan9",
        ),
        (
            MountPreflightError::Io {
                path: p.clone(),
                detail: "boom".to_owned(),
            },
            "boom",
        ),
    ];
    for (err, needle) in cases {
        let rendered = err.to_string();
        assert!(
            rendered.contains(needle),
            "expected {rendered:?} to contain {needle:?}"
        );
    }
}

#[test]
fn mount_preflight_refuses_a_missing_mountpoint() {
    let dir = MountScratchDir::new();
    let missing = dir.0.join("nope");
    let err = mount_preflight(&missing, false).expect_err("a missing path must be refused");
    assert!(matches!(err, MountPreflightError::NotFound(p) if p == missing));
}

#[test]
fn mount_preflight_refuses_a_plain_file() {
    let dir = MountScratchDir::new();
    let file = dir.0.join("plain");
    std::fs::write(&file, b"x").unwrap_or_else(|e| panic!("{e}"));
    let err = mount_preflight(&file, false).expect_err("a non-directory must be refused");
    assert!(matches!(err, MountPreflightError::NotADirectory(p) if p == file));
}

#[test]
fn mount_preflight_refuses_a_symlinked_mountpoint() {
    let dir = MountScratchDir::new();
    let target = dir.0.join("real");
    std::fs::create_dir_all(&target).unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
    let err = mount_preflight(&link, false).expect_err("a symlink must be refused");
    assert!(matches!(err, MountPreflightError::Symlink(p) if p == link));
}

#[test]
fn mount_preflight_names_the_platform_when_the_mount_check_is_unsupported() {
    // On every platform that is not Linux, `mount_preflight` runs
    // the exists/is-dir/no-symlink check (which an empty, real
    // directory PASSES), then reaches the already-mounted check —
    // which is a NAMED refusal there, never a silent
    // skip. This is the one branch of mount_preflight this
    // box can drive all the way through without a kernel.
    let dir = MountScratchDir::new();
    let err = mount_preflight(&dir.0, false);
    if cfg!(target_os = "linux") {
        // Not reachable in CI's Linux lane without a real mount
        // table fixture; recorded rather than silently skipped.
        return;
    }
    match err {
        Err(MountPreflightError::MountCheckUnsupported { os }) => {
            assert_eq!(os, std::env::consts::OS);
        }
        other => panic!("expected MountCheckUnsupported, got {other:?}"),
    }
}

// refuse_if_nonempty is exercised directly, decoupled from the
// platform gate above (which refuses before ever reaching it on
// this box).
#[test]
fn first_entry_verdict_separates_an_io_error_from_a_non_empty_directory() {
    let path = Path::new("/mnt/probe");
    assert!(first_entry_verdict::<()>(None, path).is_ok());
    assert!(matches!(
        first_entry_verdict(Some(Ok(())), path),
        Err(MountPreflightError::NotEmpty(p)) if p == path
    ));
    // A failed enumeration must report `Io`, so it cannot be mistaken
    // for a completed emptiness check.
    let failed = first_entry_verdict::<()>(
        Some(Err(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))),
        path,
    );
    assert!(
        matches!(&failed, Err(MountPreflightError::Io { path: p, .. }) if p == path),
        "a failed enumeration must be an Io refusal naming the real condition, \
         never NotEmpty: {failed:?}"
    );
}

#[test]
fn refuse_if_nonempty_accepts_an_empty_directory() {
    let dir = MountScratchDir::new();
    refuse_if_nonempty(&dir.0).unwrap_or_else(|e| panic!("{e}"));
}

#[test]
fn refuse_if_nonempty_refuses_a_directory_with_one_entry() {
    let dir = MountScratchDir::new();
    std::fs::write(dir.0.join("leftover"), b"x").unwrap_or_else(|e| panic!("{e}"));
    let err = refuse_if_nonempty(&dir.0).expect_err("a non-empty directory must be refused");
    assert!(matches!(err, MountPreflightError::NotEmpty(p) if p == dir.0));
}

// ------------------------------------- `gran umount` (Step 7)

/// A real, existing directory resolves — the ordinary
/// case this function exists to feed `findmnt`'s own absolute TARGET
/// column.
#[test]
fn resolve_for_verification_succeeds_on_a_real_directory() {
    let dir = MountScratchDir::new();
    let resolved = resolve_for_verification(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    assert!(resolved.is_absolute());
}

/// Resolution must fail closed even when only the parent is resolved:
/// a path whose PARENT cannot be resolved is a REFUSAL, never a
/// silent fallback to the argument as given. This test puts the
/// missing component in the parent, which is the part being resolved.
#[test]
fn resolve_for_verification_refuses_rather_than_falling_back() {
    let dir = MountScratchDir::new();
    let missing_parent = dir.0.join("does-not-exist").join("mountpoint");
    let err = resolve_for_verification(&missing_parent).expect_err(
        "a path whose parent cannot be canonicalized must be refused, not silently kept",
    );
    assert!(err.message.contains("could not resolve"));
    assert_eq!(
        err.class,
        granary_client::FailureClass::Io,
        "verification refusal class: resolution failure"
    );
}

/// A path that names no mountpoint is a policy refusal, not an I/O failure.
#[test]
fn resolve_for_verification_classifies_a_root_as_refused() {
    let err = resolve_for_verification(Path::new("/"))
        .expect_err("a filesystem root does not name a mountpoint");
    assert_eq!(
        err.class,
        granary_client::FailureClass::Refused,
        "verification refusal class: no mountpoint"
    );
}

/// The mountpoint's FINAL
/// component must be taken LITERALLY, never dereferenced through —
/// `granary-fuse/src/unmount.rs`'s own doc names exactly why
/// (dereferencing a live FUSE mountpoint crosses into the mounted
/// filesystem, which may be wedged: `ENOTCONN` on an aborted mount,
/// a HANG on an unanswered one). A symlink at the final component is
/// the portable, observable stand-in here for "a wedged mount would
/// otherwise be touched": if this function dereferenced it (the
/// prior, whole-target-`canonicalize` version did), the result would
/// be the symlink's TARGET directory; taking it literally, the
/// result is the symlink's own name, joined onto its (real,
/// canonicalized) parent.
#[test]
fn resolve_for_verification_does_not_dereference_the_final_component() {
    let dir = MountScratchDir::new();
    let real_target = dir.0.join("real-target");
    std::fs::create_dir_all(&real_target).unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("mnt-link");
    std::os::unix::fs::symlink(&real_target, &link).unwrap_or_else(|e| panic!("{e}"));

    let resolved = resolve_for_verification(&link).unwrap_or_else(|e| panic!("{e}"));

    let canonical_dir = std::fs::canonicalize(&dir.0).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        resolved,
        canonical_dir.join("mnt-link"),
        "the final component must be taken literally (never dereferenced) — resolving it \
         would canonicalize the whole target, which is forbidden because it can \
         cross into a wedged mount"
    );
}

/// The detach fallback must work for a mount made through a
/// symlinked ANCESTOR (not the final component, which the test above
/// already pins) — `gran mount /tmp/link/x` where `/tmp/link ->
/// /real`. `detach_unmount`'s own `resolve_target` (granary-fuse)
/// canonicalizes the parent and refuses when it disagrees with the
/// LEXICAL parent (`UnmountError::ParentNotCanonical`); handing it
/// the raw, symlink-through mountpoint would hit that refusal
/// precisely in the case the EBUSY fallback exists for.
/// `detach_target_for` must hand back the CANONICAL form instead, so
/// `resolve_target`'s own check is trivially satisfied (a canonical
/// path's parent already equals its own canonicalization).
///
/// EXECUTED mutation: capturing the raw mountpoint again (no
/// `resolve_for_verification` call) leaves this red — see the
/// session report for the quoted run.
#[test]
fn detach_target_for_resolves_through_a_symlinked_ancestor() {
    let dir = MountScratchDir::new();
    let real_target = dir.0.join("real-target");
    std::fs::create_dir_all(&real_target).unwrap_or_else(|e| panic!("{e}"));
    let link = dir.0.join("mnt-link");
    std::os::unix::fs::symlink(&real_target, &link).unwrap_or_else(|e| panic!("{e}"));
    let mountpoint = link.join("x");

    let target = detach_target_for(&mountpoint);

    let canonical_real_target =
        std::fs::canonicalize(&real_target).unwrap_or_else(|e| panic!("{e}"));
    match target {
        DetachTarget::Resolved(resolved) => assert_eq!(
            resolved,
            canonical_real_target.join("x"),
            "the detach closure must receive the CANONICAL-PARENT form, exactly what \
             resolve_target (granary-fuse) accepts — the raw, symlink-through path is what \
             ParentNotCanonical refuses"
        ),
        DetachTarget::Unavailable(msg) => {
            panic!("a symlinked ancestor must resolve, not report unavailable: {msg}")
        }
    }
}

/// The failure case: what `detach_target_for`
/// hands back when `resolve_for_verification` refuses — the same
/// message that `run_fuse_daemon` must both
/// `tracing::warn!` at startup and return from the detach closure at
/// shutdown (see `detach_target_for`'s own doc). Pinned directly, on
/// the same missing-parent case
/// `resolve_for_verification_refuses_rather_than_falling_back` above
/// already proves `resolve_for_verification` itself refuses on.
#[test]
fn detach_target_for_is_unavailable_when_resolve_for_verification_refuses() {
    let dir = MountScratchDir::new();
    let missing_parent = dir.0.join("does-not-exist").join("mountpoint");
    match detach_target_for(&missing_parent) {
        DetachTarget::Unavailable(why) => {
            assert!(
                why.message.contains("lazy-detach fallback is unavailable"),
                "the message an operator sees (and the shutdown path reports) must name WHAT is \
                 unavailable, not fail silently: {}",
                why.message
            );
            assert_eq!(
                why.class,
                granary_client::FailureClass::Io,
                "the class comes from the resolution failure, not a fixed value"
            );
        }
        DetachTarget::Resolved(p) => panic!(
            "a path whose parent cannot be canonicalized must be Unavailable, never \
             Resolved: {p:?}"
        ),
    }
}

#[test]
fn umount_preflight_verdict_authorizes_all_gran() {
    assert!(umount_preflight_verdict(Ok(TargetRows::AllGran)).is_ok());
}

/// The pre-check answering "not a granary
/// mount" is a REFUSAL, not a silent skip that lets `detach_unmount`
/// run anyway.
#[test]
fn umount_preflight_verdict_refuses_absent() {
    let err = umount_preflight_verdict(Ok(TargetRows::Absent))
        .expect_err("a target that is not a granary mount must be refused");
    assert!(err.contains("not a granary mount"));
}

/// BOTH `Mixed` shapes must be refused —
/// `umount2` detaches the TOPMOST mount regardless of whether a
/// granary mount is anywhere else in the stack — with the refusal's
/// OWN message asserted, not just `is_err()`: it must name that the
/// target carries a mount that is not granary's and that `umount2`
/// detaches the topmost one.
#[test]
fn umount_preflight_verdict_refuses_mixed_naming_the_condition() {
    for mixed in [
        TargetRows::Mixed { any_gran: true },
        TargetRows::Mixed { any_gran: false },
    ] {
        let err = umount_preflight_verdict(Ok(mixed))
            .expect_err("an over-mounted target must be refused, regardless of any_gran");
        assert!(
            err.contains("not granary's"),
            "expected the message to name that the target carries a non-granary mount: {err}"
        );
        assert!(
            err.to_lowercase().contains("topmost"),
            "expected the message to name that umount2 detaches the TOPMOST mount: {err}"
        );
    }
}

/// The "could not verify" shape must ALSO refuse — treating an
/// inconclusive pre-check as permission to proceed would reopen
/// the path that lets `detach_unmount` run without verification.
#[test]
fn umount_preflight_verdict_refuses_err() {
    let err = umount_preflight_verdict(Err(std::io::Error::other("boom")))
        .expect_err("an inconclusive pre-check must be refused, never treated as permission");
    assert!(err.contains("could not verify"));
}

#[test]
fn umount_postcheck_verdict_maps_every_target_rows_variant() {
    for (rows, still_mounted) in [
        (TargetRows::AllGran, true),
        (TargetRows::Mixed { any_gran: true }, true),
        (TargetRows::Mixed { any_gran: false }, false),
        (TargetRows::Absent, false),
    ] {
        let verdict = umount_postcheck_verdict(rows);
        assert_eq!(
            verdict.is_err(),
            still_mounted,
            "{rows:?} must {} a granary mount still present",
            if still_mounted {
                "report"
            } else {
                "not report"
            }
        );
        if let Err(why) = verdict {
            assert!(
                why.contains("still mounted"),
                "the message must name the condition, not leave it to the exit code: {why}"
            );
        }
    }
}

/// The pre-flight and the post-check must DISAGREE on `AllGran`: the
/// pre-flight authorizes it (this is unambiguously granary's mount, so
/// detach it) and the post-check refuses it (granary's mount is still
/// here after the detach, so the detach failed). A refactor that
/// unified the two into one predicate would be silent without this.
#[test]
fn the_preflight_authorizes_all_gran_and_the_postcheck_refuses_it() {
    assert!(umount_preflight_verdict(Ok(TargetRows::AllGran)).is_ok());
    assert!(umount_postcheck_verdict(TargetRows::AllGran).is_err());
}

/// On every non-Linux platform, `gran umount` is a NAMED refusal —
/// never a silent no-op, and never an attempt that quietly does
/// nothing. Runs for real on THIS box (macOS), unlike the Linux
/// half of this verb, which only CI can exercise.
///
/// The exit-code assertion alone
/// was EXECUTED to stay green after deleting the `eprintln!` that
/// makes this refusal NAMED rather than silent — the "NAMED, never
/// silent" half of this very test's own name and doc was unasserted.
/// `cmd_umount`'s `err` sink (see its own doc) is what makes the
/// message itself assertable here, without capturing real process
/// stderr.
#[test]
fn cmd_umount_is_a_named_refusal_off_linux() {
    if cfg!(target_os = "linux") {
        return;
    }
    let dir = MountScratchDir::new();
    let mut err = Vec::new();
    let code = cmd_umount(&dir.0, &mut err);
    assert_eq!(
        code,
        mount_exit_code(MountOutcome::RuntimeFailure),
        "gran umount off Linux must exit 1 (RuntimeFailure), never 0"
    );
    let message = String::from_utf8_lossy(&err);
    assert!(
        !message.is_empty(),
        "the refusal must be NAMED, never a silent no-op"
    );
    assert!(message.contains("not supported on"), "got: {message:?}");
}

/// `cmd_umount_with_credentials` must refuse a
/// set-ID invocation on EVERY platform — this check runs before the
/// `#[cfg(target_os = "linux")]` split, so it is asserted directly
/// here rather than only on the non-Linux arm like the test above.
/// The failure exit code alone is not decisive (it happens to match
/// the non-Linux "unsupported" refusal too), so the sink's own
/// MESSAGE is asserted to name the actual set-ID condition, proving
/// this is the NEW refusal firing and not some other one.
#[test]
fn cmd_umount_with_credentials_refuses_set_id_execution() {
    let dir = MountScratchDir::new();
    let mut err = Vec::new();
    let tainted = ProcessCredentials {
        ruid: 1_000,
        euid: 1_001,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    };
    let code = cmd_umount_with_credentials(&dir.0, &tainted, &mut err);
    assert_eq!(
        code,
        mount_exit_code(MountOutcome::RuntimeFailure),
        "a set-ID gran umount invocation must fail, never proceed to detach_unmount"
    );
    let message = String::from_utf8_lossy(&err);
    assert!(
        message.contains("real uid 1000 differs from effective uid 1001"),
        "the sink must name the specific set-ID condition that fired: {message}"
    );
}

// ------------------------------------------ Step 4: the option set

/// granary-fuse's tests already pin every property this step's three
/// comments describe (`session_config`'s
/// `shipped_option_set_is_ro_nosuid_nodev_and_not_noexec` and
/// `acl_is_all_when_allow_other_and_owner_otherwise`, in
/// `granary-fuse/src/options/tests.rs`);
/// the parsing side's own change there is the explanatory comments
/// themselves, not new behaviour, so no new test is added in THIS
/// crate for it. Recorded here so a reader of this file's test list
/// is not left wondering where that coverage went.

// ------------------------------------------ Step 8: the exit-code mapping

#[test]
fn mount_exit_code_clean_is_zero() {
    assert_eq!(mount_exit_code(MountOutcome::Clean), ExitCode::from(0));
}

#[test]
fn mount_exit_code_runtime_failure_is_one() {
    assert_eq!(
        mount_exit_code(MountOutcome::RuntimeFailure),
        ExitCode::from(1)
    );
}

#[test]
fn mount_exit_code_usage_matches_usage_fn() {
    assert_eq!(mount_exit_code(MountOutcome::Usage), usage());
    assert_eq!(mount_exit_code(MountOutcome::Usage), ExitCode::from(2));
}

#[test]
fn mount_exit_code_cache_close_failed_is_distinct_from_the_other_three() {
    let cache_close = mount_exit_code(MountOutcome::CacheCloseFailed);
    assert_eq!(cache_close, ExitCode::from(3));
    assert_ne!(cache_close, mount_exit_code(MountOutcome::Clean));
    assert_ne!(cache_close, mount_exit_code(MountOutcome::RuntimeFailure));
    assert_ne!(cache_close, mount_exit_code(MountOutcome::Usage));
}

// --------------------------------- the shutdown coordinator (Step 7)

/// A report with `outcome`, as the shutdown thread or the handle answers it.
fn report_of(outcome: granary_client::ShutdownOutcome) -> granary_client::ShutdownReport {
    granary_client::ShutdownReport {
        outcome,
        cut: matches!(
            outcome,
            granary_client::ShutdownOutcome::Incomplete(granary_client::ShutdownCause::Deadline)
        )
        .then_some(granary_client::ShutdownCut::Bound),
        residue: None,
        elapsed_ms: 12,
    }
}

fn committed() -> granary_client::ShutdownReport {
    report_of(granary_client::ShutdownOutcome::Committed(7))
}

/// The exit table, read as its rows say, first match wins: 5 fenced, 4
/// stopped, then 1 for a failed or lost shutdown, an engine with no report,
/// a session that did not end clean or a daemon that gave up with the mount
/// listed or unverifiable, or an engine-less store left unflushed; then 3
/// for a cache that did not close or a daemon that gave up with the mount
/// gone; else 0.
fn exit_by_the_table(
    report: Option<granary_client::ShutdownReport>,
    engine: bool,
    session: &SessionVerdict,
    cache: Option<&Result<(), String>>,
) -> u8 {
    use granary_client::{ShutdownCause as C, ShutdownOutcome as O};
    match report.map(|report| report.outcome) {
        Some(O::Fenced) => return 5,
        Some(O::Incomplete(C::Deadline)) => return 4,
        Some(O::Incomplete(_)) => return 1,
        None if engine => return 1,
        _ => (),
    }
    let unflushed = matches!(cache, Some(Err(error)) if error.starts_with("WritableShutdownCoordinationFailed:"));
    let gone = matches!(session, SessionVerdict::NotJoined { listed: Ok(false) });
    let clean = matches!(
        session,
        SessionVerdict::Joined(granary_fuse::SessionEnd::Clean)
    );
    if unflushed || !(clean || gone) {
        1
    } else if gone || matches!(cache, Some(Err(_))) {
        3
    } else {
        0
    }
}

/// Every report a daemon can hold, with whether an engine was attached: a
/// read-only mount has neither.
fn table_reports() -> Vec<(Option<granary_client::ShutdownReport>, bool)> {
    use granary_client::{FailureClass, ShutdownCause as C, ShutdownCut, ShutdownOutcome as O};
    let mut signal = report_of(O::Incomplete(C::Deadline));
    signal.cut = Some(ShutdownCut::Signal);
    vec![
        (None, false),
        (None, true),
        (Some(committed()), true),
        (Some(report_of(O::Clean)), true),
        (Some(report_of(O::Incomplete(C::Deadline))), true),
        (Some(signal), true),
        (
            Some(report_of(O::Incomplete(C::Failed(
                FailureClass::Unavailable,
            )))),
            true,
        ),
        (Some(report_of(O::Incomplete(C::Internal))), true),
        (Some(report_of(O::Fenced)), true),
    ]
}

/// Every session verdict, built fresh: an `io::Error` is not `Clone`.
fn table_sessions() -> Vec<fn() -> SessionVerdict> {
    use granary_fuse::SessionEnd as E;
    vec![
        || SessionVerdict::Joined(E::Clean),
        || SessionVerdict::Joined(E::Forced),
        || SessionVerdict::Joined(E::Survived),
        || {
            SessionVerdict::Joined(E::UnmountFailed(std::io::Error::from_raw_os_error(
                libc::EBUSY,
            )))
        },
        || {
            SessionVerdict::Joined(E::Failed(std::io::Error::from_raw_os_error(
                libc::ECONNABORTED,
            )))
        },
        || SessionVerdict::Joined(E::Unverified(std::io::Error::other("mountinfo"))),
        || SessionVerdict::Panicked,
        || SessionVerdict::NotJoined { listed: Ok(false) },
        || SessionVerdict::NotJoined { listed: Ok(true) },
        || SessionVerdict::NotJoined {
            listed: Err(std::io::Error::other("mountinfo")),
        },
    ]
}

fn table_caches() -> Vec<Option<Result<(), String>>> {
    vec![
        None,
        Some(Ok(())),
        Some(Err("ENOSPC".to_owned())),
        Some(Err(
            "WritableShutdownCoordinationFailed: WritableRecoveryRequired; cache=closed".to_owned(),
        )),
        Some(Err(
            "WritableShutdownCoordinationFailed: WritableRecoveryRequired; cache=failed".to_owned(),
        )),
    ]
}

/// The daemon's exit over every report, session verdict and cache result
/// it can see, against the table read row by row, with the rows a script
/// depends on spelled out: 5 and 4 are distinct and outrank a failed
/// session, a released shutdown whose daemon gave up with the mount gone is
/// 3, a no-engine store left unflushed is 1, and an engine-less read-only
/// mount exits by its session and cache alone. A table that reported a
/// stopped shutdown as a failure, a fence as a stop, a failed session
/// above a kept store, or a daemon that gave up with the mount gone as a
/// failure, fails a spelled-out row.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one row holds the whole table's sweep and the rows a script depends on, \
              spelled out beside it"
)]
fn mount_shutdown_outcome_table() {
    use granary_client::{FailureClass, ShutdownCause as C, ShutdownCut, ShutdownOutcome as O};
    let code = |outcome: MountOutcome| match outcome {
        MountOutcome::Clean => 0,
        MountOutcome::RuntimeFailure => 1,
        MountOutcome::Usage => 2,
        MountOutcome::CacheCloseFailed => 3,
        MountOutcome::Stopped => 4,
        MountOutcome::Fenced => 5,
    };
    let mut cases = 0;
    for (report, engine) in table_reports() {
        for session in table_sessions() {
            for cache in table_caches() {
                let expected = exit_by_the_table(report, engine, &session(), cache.as_ref());
                assert_eq!(
                    code(mount_shutdown_outcome(
                        report,
                        engine,
                        &session(),
                        cache.clone()
                    )),
                    expected,
                    "report={report:?}, engine={engine}, session={:?}, cache={cache:?}",
                    session()
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 9 * 10 * 5);
    let spelled: Vec<(&str, MountOutcome)> = vec![
        (
            "committed, joined clean, cache closed",
            mount_shutdown_outcome(
                Some(committed()),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Ok(())),
            ),
        ),
        (
            "stopped, session panicked",
            mount_shutdown_outcome(
                Some(report_of(O::Incomplete(C::Deadline))),
                true,
                &SessionVerdict::Panicked,
                None,
            ),
        ),
        (
            "fenced, session survived",
            mount_shutdown_outcome(
                Some(report_of(O::Fenced)),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Survived),
                None,
            ),
        ),
        (
            "committed, not joined, mount gone",
            mount_shutdown_outcome(
                Some(committed()),
                true,
                &SessionVerdict::NotJoined { listed: Ok(false) },
                None,
            ),
        ),
        (
            "committed, not joined, mount listed",
            mount_shutdown_outcome(
                Some(committed()),
                true,
                &SessionVerdict::NotJoined { listed: Ok(true) },
                None,
            ),
        ),
        (
            "no engine, joined clean, store left unflushed",
            mount_shutdown_outcome(
                None,
                false,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Err(
                    "WritableShutdownCoordinationFailed: WritableRecoveryRequired; cache=closed"
                        .to_owned(),
                )),
            ),
        ),
        (
            "read-only, joined clean, cache failed",
            mount_shutdown_outcome(
                None,
                false,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Err("ENOSPC".to_owned())),
            ),
        ),
        (
            "an engine with no report",
            mount_shutdown_outcome(
                None,
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Ok(())),
            ),
        ),
    ];
    assert_eq!(
        spelled
            .into_iter()
            .map(|(row, outcome)| (row, code(outcome)))
            .collect::<Vec<_>>(),
        vec![
            ("committed, joined clean, cache closed", 0),
            ("stopped, session panicked", 4),
            ("fenced, session survived", 5),
            ("committed, not joined, mount gone", 3),
            ("committed, not joined, mount listed", 1),
            ("no engine, joined clean, store left unflushed", 1),
            ("read-only, joined clean, cache failed", 3),
            ("an engine with no report", 1),
        ]
    );
    let unread = || SessionVerdict::NotJoined {
        listed: Err(std::io::Error::other("mountinfo")),
    };
    let mut signal = report_of(O::Incomplete(C::Deadline));
    signal.cut = Some(ShutdownCut::Signal);
    let more: Vec<(&str, MountOutcome)> = vec![
        (
            "fenced, not joined, mountinfo unread",
            mount_shutdown_outcome(Some(report_of(O::Fenced)), true, &unread(), None),
        ),
        (
            "stopped, not joined, mountinfo unread",
            mount_shutdown_outcome(
                Some(report_of(O::Incomplete(C::Deadline))),
                true,
                &unread(),
                None,
            ),
        ),
        (
            "stopped by a signal, joined clean, cache failed",
            mount_shutdown_outcome(
                Some(signal),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Err("ENOSPC".to_owned())),
            ),
        ),
        (
            "clean, not joined, mountinfo unread",
            mount_shutdown_outcome(Some(report_of(O::Clean)), true, &unread(), None),
        ),
        (
            "committed, joined unverified",
            mount_shutdown_outcome(
                Some(committed()),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Unverified(
                    std::io::Error::other("mountinfo"),
                )),
                Some(Ok(())),
            ),
        ),
        (
            "committed, joined clean, cache failed",
            mount_shutdown_outcome(
                Some(committed()),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Err("ENOSPC".to_owned())),
            ),
        ),
        (
            "failed step, joined clean, cache closed",
            mount_shutdown_outcome(
                Some(report_of(O::Incomplete(C::Failed(
                    FailureClass::Unavailable,
                )))),
                true,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Ok(())),
            ),
        ),
        (
            "lost sequence, not joined, mount gone",
            mount_shutdown_outcome(
                Some(report_of(O::Incomplete(C::Internal))),
                true,
                &SessionVerdict::NotJoined { listed: Ok(false) },
                None,
            ),
        ),
        (
            "read-only, not joined, mount listed",
            mount_shutdown_outcome(
                None,
                false,
                &SessionVerdict::NotJoined { listed: Ok(true) },
                None,
            ),
        ),
        (
            "read-only, not joined, mount gone",
            mount_shutdown_outcome(
                None,
                false,
                &SessionVerdict::NotJoined { listed: Ok(false) },
                None,
            ),
        ),
        (
            "read-only, joined clean, cache closed",
            mount_shutdown_outcome(
                None,
                false,
                &SessionVerdict::Joined(granary_fuse::SessionEnd::Clean),
                Some(Ok(())),
            ),
        ),
    ];
    assert_eq!(
        more.into_iter()
            .map(|(row, outcome)| (row, code(outcome)))
            .collect::<Vec<_>>(),
        vec![
            ("fenced, not joined, mountinfo unread", 5),
            ("stopped, not joined, mountinfo unread", 4),
            ("stopped by a signal, joined clean, cache failed", 4),
            ("clean, not joined, mountinfo unread", 1),
            ("committed, joined unverified", 1),
            ("committed, joined clean, cache failed", 3),
            ("failed step, joined clean, cache closed", 1),
            ("lost sequence, not joined, mount gone", 1),
            ("read-only, not joined, mount listed", 1),
            ("read-only, not joined, mount gone", 3),
            ("read-only, joined clean, cache closed", 0),
        ],
        "the design's exit table, row by row"
    );
}

/// Collects the JSON records a closure emits, at debug and above.
#[derive(Clone, Default)]
struct EmittedEvents(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Write for EmittedEvents {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for EmittedEvents {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn emitted_records<R>(run: impl FnOnce() -> R) -> (R, Vec<String>) {
    let output = EmittedEvents::default();
    let subscriber = granary_client::closed_subscriber(
        granary_client::LogFormat::Json,
        tracing_subscriber::EnvFilter::new("debug"),
        output.clone(),
    );
    let result = tracing::subscriber::with_default(subscriber, run);
    let bytes = output
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let records = String::from_utf8(bytes)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    (result, records)
}

fn emitted_events<R>(run: impl FnOnce() -> R) -> (R, Vec<String>) {
    let (result, records) = emitted_records(run);
    let names = records
        .into_iter()
        .map(|line| {
            line.split_once("\"event\":\"")
                .and_then(|(_, rest)| rest.split('"').next())
                .unwrap_or(&line)
                .to_owned()
        })
        .collect();
    (result, names)
}

const RACE_EVENT: &str = "client.gran.mount.the.fuse.session.ended.econnaborted.racing.its.unmount";
const ERROR_EVENT: &str = "client.gran.mount.the.fuse.session.ended.with.an.error";
const PANIC_EVENT: &str = "client.gran.mount.the.fuse.session.thread.panicked";
const NOT_JOINED_EVENT: &str = "client.gran.mount.the.fuse.session.did.not.end.after.its.unmount";

fn not_joined_record(listed: &str, connection: &str) -> String {
    format!(
        r#"{{"level":"WARN","target":"granary_client::event","event":"{NOT_JOINED_EVENT}","message":"gran mount: stopped waiting for the FUSE session to end after its unmount","listed":"{listed}","connection":"{connection}"}}"#
    )
}

/// The verdict's name, for a row's tuple: an `io::Error` has no `PartialEq`.
fn verdict_name(verdict: &SessionVerdict) -> &'static str {
    use granary_fuse::SessionEnd as E;
    match verdict {
        SessionVerdict::Joined(E::Clean) => "clean",
        SessionVerdict::Joined(E::Forced) => "forced",
        SessionVerdict::Joined(E::UnmountFailed(_)) => "unmount failed",
        SessionVerdict::Joined(E::Failed(_)) => "failed",
        SessionVerdict::Joined(E::Survived) => "survived",
        SessionVerdict::Joined(E::Unverified(_)) => "unverified",
        SessionVerdict::Panicked => "panicked",
        SessionVerdict::NotJoined { listed: Ok(false) } => "not joined, gone",
        SessionVerdict::NotJoined { listed: Ok(true) } => "not joined, listed",
        SessionVerdict::NotJoined { listed: Err(_) } => "not joined, unread",
    }
}

/// Every join goes through the classifier, with the mount table read after
/// it, and its diagnostic follows the verdict: a teardown race with the
/// mount gone is a clean end recorded at debug level, a clean end with the
/// mount gone emits nothing, and everything else is a warned failure — a
/// clean end with the mount still listed (survived) or the table unreadable
/// (unverified) included. A join never emits the grace-expiry warning.
/// The plausible wrong wirings each fail a row: every error a failure (the
/// race row), every `ECONNABORTED` clean (the listed and unreadable rows),
/// the errno ignored (the `EIO` row), a clean loop end never classified (the
/// survived and unverified rows), the table read only for an error end (the
/// clean rows' read counts), and the race left unrecorded or warned about
/// (the race row's events).
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of joins, each with its verdict, reads and events"
)]
fn session_verdict_classifies_every_join_with_its_diagnostic() {
    type Row = (
        &'static str,
        std::io::Result<()>,
        Option<std::thread::Result<std::io::Result<()>>>,
        std::io::Result<bool>,
        (&'static str, usize, Vec<&'static str>),
    );
    let race = || Err(std::io::Error::from_raw_os_error(libc::ECONNABORTED));
    let panicked: std::thread::Result<std::io::Result<()>> = std::thread::spawn(|| {
        panic!("simulated session thread panic, for the join verdict's own test")
    })
    .join();
    let rows: Vec<Row> = vec![
        (
            "clean end, mount gone",
            Ok(()),
            Some(Ok(Ok(()))),
            Ok(false),
            ("clean", 1, vec![]),
        ),
        (
            "clean end, mount listed",
            Ok(()),
            Some(Ok(Ok(()))),
            Ok(true),
            ("survived", 1, vec![ERROR_EVENT]),
        ),
        (
            "clean end, mountinfo unreadable",
            Ok(()),
            Some(Ok(Ok(()))),
            Err(std::io::Error::other("mountinfo unreadable")),
            ("unverified", 1, vec![ERROR_EVENT]),
        ),
        (
            "race, mount gone",
            Ok(()),
            Some(Ok(race())),
            Ok(false),
            ("clean", 1, vec![RACE_EVENT]),
        ),
        (
            "race, mount listed",
            Ok(()),
            Some(Ok(race())),
            Ok(true),
            ("failed", 1, vec![ERROR_EVENT]),
        ),
        (
            "race, mountinfo unreadable",
            Ok(()),
            Some(Ok(race())),
            Err(std::io::Error::other("mountinfo unreadable")),
            ("failed", 1, vec![ERROR_EVENT]),
        ),
        (
            "other errno, mount gone",
            Ok(()),
            Some(Ok(Err(std::io::Error::from_raw_os_error(libc::EIO)))),
            Ok(false),
            ("failed", 1, vec![ERROR_EVENT]),
        ),
        (
            "failed unmount, race, mount listed",
            Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
            Some(Ok(race())),
            Ok(true),
            ("unmount failed", 1, vec![ERROR_EVENT]),
        ),
        (
            "panic",
            Ok(()),
            Some(panicked),
            Ok(false),
            ("panicked", 0, vec![PANIC_EVENT]),
        ),
    ];
    let mut cases = 0;
    for (row, unmount, joined, listed, expected) in rows {
        let mut reads = 0;
        let (verdict, events) = emitted_events(|| {
            session_verdict(
                unmount,
                joined,
                || {
                    reads += 1;
                    listed
                },
                || unreachable!("a joined session needs no connection check"),
            )
        });
        assert_eq!(
            (verdict_name(&verdict), reads, events),
            (
                expected.0,
                expected.1,
                expected
                    .2
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect::<Vec<_>>()
            ),
            "{row}: (verdict, mount-table reads, events)"
        );
        cases += 1;
    }
    assert_eq!(cases, 9);
}

/// A daemon that stops waiting reads both observations and warns once. The
/// differing rows catch a fixed label or a skipped read of either observation.
#[test]
fn session_verdict_warns_once_when_the_session_did_not_join() {
    let rows = [
        (
            Ok(()),
            Ok(false),
            Some(true),
            "not joined, gone",
            "gone",
            "alive",
        ),
        (
            Err(std::io::Error::from_raw_os_error(libc::EBUSY)),
            Ok(true),
            Some(false),
            "not joined, listed",
            "listed",
            "gone",
        ),
        (
            Ok(()),
            Err(std::io::Error::other("mountinfo unreadable")),
            None,
            "not joined, unread",
            "unknown",
            "unknown",
        ),
    ];
    let mut cases = 0;
    for (unmount, listed, connection, verdict, listed_label, connection_label) in rows {
        let mut table_reads = 0;
        let mut connection_reads = 0;
        let (actual_verdict, records) = emitted_records(|| {
            session_verdict(
                unmount,
                None,
                || {
                    table_reads += 1;
                    listed
                },
                || {
                    connection_reads += 1;
                    connection
                },
            )
        });
        assert_eq!(
            (
                verdict_name(&actual_verdict),
                table_reads,
                connection_reads,
                records
            ),
            (
                verdict,
                1,
                1,
                vec![not_joined_record(listed_label, connection_label)]
            ),
            "{verdict}: (verdict, mount-table reads, connection reads, records)"
        );
        cases += 1;
    }
    assert_eq!(cases, 3);
}

/// The unmount the classifier weighs: the kernel's own on the session-end
/// path, else the daemon's, or its detach when the unmount failed.
#[test]
fn unmount_evidence_by_path() {
    let failed = || Err(std::io::Error::from_raw_os_error(libc::EBUSY));
    let rows = [
        (
            "session end, unmount failed",
            unmount_evidence(
                Exit::SessionEnded,
                failed(),
                Some(Err(granary_client::FailureClass::Io)),
            )
            .is_ok(),
            true,
        ),
        (
            "signal, unmount ok",
            unmount_evidence(Exit::Signal("SIGTERM"), Ok(()), None).is_ok(),
            true,
        ),
        (
            "signal, unmount failed, detached",
            unmount_evidence(Exit::Signal("SIGTERM"), failed(), Some(Ok(()))).is_ok(),
            true,
        ),
        (
            "signal, unmount and detach failed",
            unmount_evidence(
                Exit::Signal("SIGTERM"),
                failed(),
                Some(Err(granary_client::FailureClass::Io)),
            )
            .is_ok(),
            false,
        ),
    ];
    for (row, got, want) in rows {
        assert_eq!(got, want, "{row}");
    }
}

/// A capture that fails warns once with its class and is returned as the
/// error the session's end reads; an unavailable detach target, already
/// warned about at startup, is returned as an error without a second warning.
#[test]
fn capture_mount_identity_warns_once_and_keeps_the_error() {
    const CAPTURE_EVENT: &str = "client.gran.mount.could.not.capture.the.mount.identity";
    let scratch = crate::tests::ScratchDir::new();
    let not_a_mount = DetachTarget::Resolved(scratch.0.clone());
    let unavailable = DetachTarget::Unavailable(VerifyRefusal::io("target refused".to_owned()));
    let mut cases = 0;
    for (row, target, events) in [
        ("not a mount", not_a_mount, vec![CAPTURE_EVENT.to_owned()]),
        ("unavailable target", unavailable, vec![]),
    ] {
        let (captured, emitted) = emitted_events(|| capture_mount_identity(&target));
        assert_eq!(
            (captured.is_err(), emitted),
            (true, events),
            "{row}: (capture failed, events)"
        );
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// The session-ended notification must survive a panic. RED (without
/// the guard): with the send as a bare statement after
/// `fuser_session.run()`, the panic below skips the send entirely. In
/// the daemon that `recv()` then blocks forever, because the two signal
/// threads still hold live senders; in this fixture the moved `tx` is
/// the only sender and drops during the unwind, so `rx.recv()` returns
/// `Err` at once and the assertion below fails with "the guard did not
/// send on unwind".
/// GREEN (with `SessionEndedGuard`): the guard's
/// `Drop` runs during the unwind, `rx.recv()` returns immediately,
/// and this test finishes in milliseconds.
#[test]
fn session_ended_guard_sends_even_when_the_thread_panics() {
    let (tx, rx) = std::sync::mpsc::channel::<Exit>();
    let handle = std::thread::spawn(move || {
        let _guard = SessionEndedGuard(tx);
        panic!("simulated Session::run panic, for SessionEndedGuard's own test");
    });
    let joined = handle.join();
    assert!(
        joined.is_err(),
        "fixture precondition: the spawned thread must actually have panicked"
    );
    assert_eq!(
        rx.recv()
            .unwrap_or_else(|e| panic!("the guard did not send on unwind: {e}")),
        Exit::SessionEnded
    );
}

/// Recover the recorded close failure even when the mutex is
/// poisoned. The closure writes a value and panics while holding
/// the lock, so the test reaches the recovery path with a poisoned
/// mutex. Reading poison as `None` hides the close failure as
/// "destroy never ran". With no run failure, `mount_shutdown_outcome`
/// then reports a clean shutdown: exit 0 instead of 3.
#[test]
fn read_cache_close_slot_recovers_the_value_from_a_poisoned_mutex() {
    let slot: std::sync::Mutex<Option<Result<(), String>>> = std::sync::Mutex::new(None);
    let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut guard = slot.lock().unwrap_or_else(|e| panic!("{e}"));
        *guard = Some(Err("cache close failed".to_owned()));
        panic!("simulated panic while holding the lock, to poison it for real");
    }));
    assert!(
        poison_result.is_err(),
        "fixture precondition: the closure must actually have panicked while holding the lock"
    );
    assert!(
        slot.is_poisoned(),
        "fixture precondition: the mutex must actually be poisoned"
    );
    let recovered = read_cache_close_slot(&slot);
    assert_eq!(
        recovered,
        Some(Err("cache close failed".to_owned())),
        "the value written just before the poisoning panic must still be readable"
    );
}

/// The WRITE-side mirror of the poisoning test above: a second thread
/// panics while holding the lock, then the test checks that writing
/// the close failure survives that poisoning. Skipping the write
/// leaves `None`, indistinguishable from "destroy never ran". With
/// no run failure, `mount_shutdown_outcome` then reports a clean
/// shutdown: exit 0 instead of 3.
#[test]
fn write_cache_close_slot_recovers_a_poisoned_mutex() {
    let slot: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let slot_poisoner = std::sync::Arc::clone(&slot);
    let handle = std::thread::spawn(move || {
        let _guard = slot_poisoner.lock().unwrap_or_else(|e| panic!("{e}"));
        panic!("simulated panic while holding the lock, to poison it for real");
    });
    let joined = handle.join();
    assert!(
        joined.is_err(),
        "fixture precondition: the spawned thread must actually have panicked while holding \
         the lock"
    );
    assert!(
        slot.is_poisoned(),
        "fixture precondition: the mutex must actually be poisoned"
    );
    write_cache_close_slot(&slot, Err("boom".to_owned()));
    let recorded = read_cache_close_slot(&slot);
    assert_eq!(
        recorded,
        Some(Err("boom".to_owned())),
        "the write must land even though the slot's mutex was poisoned by an unrelated panic"
    );
}

// -------------------------- Signal readiness: two reports or disconnection

/// The ordinary case: both signal threads report readiness, and
/// `await_signal_readiness` returns having consumed exactly the two
/// reports — nothing left buffered in the channel.
#[test]
fn await_signal_readiness_returns_after_two_reports() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(()).unwrap_or_else(|e| panic!("{e}"));
    tx.send(()).unwrap_or_else(|e| panic!("{e}"));
    await_signal_readiness(&rx);
    // `tx` is kept alive past the call (not dropped) so `try_recv`'s
    // `Empty` means what it says: nothing left buffered, senders
    // still live — an all-senders-dropped empty channel answers
    // `Disconnected` instead, which would conflate "drained cleanly"
    // with "the other end went away".
    assert_eq!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty),
        "exactly two reports must be consumed, no more"
    );
    drop(tx);
}

/// >>> THE REPORTING THREAD MUST RELEASE ITS SENDER BEFORE IT PARKS. <<<
///
/// `await_signal_readiness` reads exactly twice and treats `Err` as "a report
/// will never come". `Err` arrives only when EVERY `Sender` is gone — so if
/// the thread that DID report is still holding its clone while parked in
/// `block_on`, a sibling that dies before reporting leaves one live sender
/// behind one buffered report, and the second `recv()` blocks.
///
/// REPRODUCED before this test was written, with the shipped function copied
/// verbatim into a standalone program and a watchdog: "winner reports and
/// PARKS; loser dies before sending" never returns, while "every sender
/// dropped" does. The older test below models the second and cannot reach the
/// first.
///
/// This asserts the OWNERSHIP property synchronously, from inside the wait
/// itself, so there is no race and no timeout-shaped kill: the wait future is
/// polled only after `report_then_wait` has sent AND dropped, so a second
/// `try_recv` must see `Disconnected`. Without the drop it sees `Empty`.
#[test]
fn report_then_wait_releases_its_sender_before_it_starts_waiting() {
    let (tx, rx) = std::sync::mpsc::channel();
    // No `enable_all()`: this future does one send, one drop and a body that is ready
    // on its first poll. No IO, no timer, no signal — matching the drivers to what is
    // exercised is the same claim the doc above makes about having no timeout.
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    rt.block_on(super::report_then_wait(tx, async {
        assert_eq!(
            rx.try_recv(),
            Ok(()),
            "the report must be buffered and readable"
        );
        assert_eq!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected),
            "the reporting thread must have RELEASED its sender before waiting; while it holds \
             one, a sibling that dies before reporting cannot disconnect the channel and \
             await_signal_readiness blocks on its second read"
        );
    }));
}

/// >>> THE PROPERTY `report_then_wait` CLAIMS, COMPOSED END TO END. <<<
///
/// The row above asserts one instant of ownership from inside the wait, which
/// is a PROXY. This puts the three real pieces together: a thread that reports
/// through [`super::report_then_wait`] and then waits on a future that never
/// completes, a sibling clone dropped without ever sending, and
/// `await_signal_readiness` — which must RETURN.
///
/// Without the release this blocks forever. A refactor that re-parks a
/// reporting thread while it still holds its sender fails the proxy above
/// at once (its second `try_recv` sees `Empty`, not `Disconnected`) and
/// hangs this row until nextest's timeout kills it.
///
/// It is deterministic: the reporting thread's send happens before
/// `report_then_wait` returns its future at all, so by the time `sibling` is
/// dropped the only question is whether the reporter released its clone.
#[test]
fn await_signal_readiness_returns_when_a_reporter_waits_and_its_sibling_dies() {
    let (tx, rx) = std::sync::mpsc::channel();
    let sibling = tx.clone();
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    let parked = std::thread::spawn(move || {
        // `pending()` never completes: this thread is the one that reports and then
        // waits for a signal that never comes, exactly like the losing signal thread.
        rt.block_on(super::report_then_wait(tx, std::future::pending::<()>()));
    });
    drop(sibling); // the thread that died before it could report
    await_signal_readiness(&rx); // must RETURN; an unreleased sender blocks it here
    drop(parked); // it is still parked, and the process would end it — as in production
}

/// A producer thread that ends
/// WITHOUT ever reporting — the shape a panic before the first send
/// would take — must not hang the wait. `recv()` on an
/// all-senders-dropped channel returns `Err` immediately (no timing
/// dependency), which is the deterministic mechanism this test
/// exercises directly: one real report arrives, the second sender is
/// dropped without ever sending, and `await_signal_readiness` must
/// still return.
#[test]
fn await_signal_readiness_does_not_hang_when_a_report_never_arrives() {
    let (tx, rx) = std::sync::mpsc::channel();
    let never_reports = tx.clone();
    tx.send(()).unwrap_or_else(|e| panic!("{e}"));
    drop(tx);
    drop(never_reports); // the thread that died pre-send
    // The `drop(tx)` above is a FAITHFUL model now and was not always: until
    // `report_then_wait` landed, the thread that DID report kept its sender while
    // parked, so one sender stayed alive and this row could not be reached in
    // production. It is reachable because the reporter releases its clone; the row
    // that holds that open is
    // `await_signal_readiness_returns_when_a_reporter_waits_and_its_sibling_dies`.
    await_signal_readiness(&rx); // must return, not hang
}

/// The loop bound is exactly two, not "keep reading until the
/// channel closes" — proven by keeping a THIRD sender alive past the
/// two real reports. The third sender is synthetic: it never sends
/// and stays alive to make a third receive block. If
/// `await_signal_readiness` read a third time here, this call would
/// block forever, since `_still_parked` never sends and is never
/// dropped until the test function returns. **This is a
/// timeout-shaped kill, not an assertion**: returning at all is the
/// proof, and nextest's own per-test timeout is what would end this
/// test on a regression that reads too many times — flagged per this
/// round's own rule, since a hang-shaped property has no
/// non-blocking proof available without extra tooling this crate
/// does not depend on.
#[test]
fn await_signal_readiness_reads_no_more_than_two_reports() {
    let (tx, rx) = std::sync::mpsc::channel();
    let _still_parked = tx.clone();
    tx.send(()).unwrap_or_else(|e| panic!("{e}"));
    tx.send(()).unwrap_or_else(|e| panic!("{e}"));
    await_signal_readiness(&rx);
}

/// `cmd_mount` refuses backgrounding (the default, no `--foreground`)
/// BEFORE anything else runs — no pre-flight, no store, no network —
/// so this is real, cross-platform coverage of `cmd_mount` itself,
/// unlike the daemon body proper (Linux-only, the podman/CI harness).
#[test]
fn cmd_mount_refuses_backgrounding_before_touching_anything_else() {
    // `cmd_mount`'s own exit code alone cannot distinguish this
    // refusal from several OTHER early returns that share
    // RuntimeFailure — see mount_requires_foreground's own doc — so
    // the DECISIVE assertion is on the pure function directly,
    // below. This one still proves `cmd_mount` actually WIRES it in
    // (a real MountArgs, a real call, the real exit code), on a
    // mountpoint that does not exist: if the foreground gate did
    // NOT fire first, the next step (pre-flight) would ALSO refuse
    // with RuntimeFailure, so this alone would not catch the gate
    // being skipped — mount_requires_foreground_* below is what
    // does that.
    let key = root_key_str();
    // This test's subject is the foreground
    // gate, which sits AFTER the
    // breakage-required gate — arm it explicitly so the foreground
    // gate is what actually fires on a feature-on build, the same
    // way `mount_attempt_with_credentials_refuses_missing_
    // breakage_...` proves the breakage gate itself, ahead of this
    // one.
    #[cfg(not(feature = "conformance-breakage"))]
    let args = mount_argv(&["--root-key", &key, "--support-bundle"]);
    #[cfg(feature = "conformance-breakage")]
    let args = mount_argv(&[
        "--root-key",
        &key,
        "--support-bundle",
        "--breakage",
        granary_fuse::Breakage::TruncateRead.name(),
    ]);
    let margs = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(!margs.foreground, "fixture precondition: no --foreground");
    assert!(
        margs.support_bundle,
        "fixture precondition: support opted in"
    );
    assert_eq!(
        cmd_mount(&margs, &mut Vec::new()),
        mount_exit_code(MountOutcome::RuntimeFailure)
    );
}

#[test]
fn mount_requires_foreground_refuses_the_default_and_accepts_foreground() {
    assert!(mount_requires_foreground(true).is_none());
    let message = mount_requires_foreground(false).unwrap_or_else(|| panic!("must refuse"));
    assert!(message.contains("--foreground") && message.contains("not implemented"));
}

/// `gran mount <existing-nonempty-dir>` on real args, one field at a
/// time — matches `mount_argv`'s own shape but with the SECOND
/// positional (mountpoint) overridden to a real scratch directory,
/// since `mount_argv` always uses `/mnt`.
fn mount_argv_at(mountpoint: &Path, extra: &[&str]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        osstr("vol"),
        OsString::from(mountpoint.as_os_str()),
        osstr("--endpoint"),
        osstr("https://h"),
        osstr("--pin"),
    ];
    argv.push(osstr(&a_pin()));
    argv.extend(extra.iter().map(|s| osstr(s)));
    argv
}

// -------------------------- Missing breakage is refused before set-ID

/// A feature build reaching
/// `mount_attempt_with_credentials` with `breakage: None` must be
/// refused BEFORE any side effect — before EVEN the set-ID check
/// (whose own tests follow, under the set-ID refusal
/// banner below). Tainted credentials would normally win as
/// `SetIdExecution`; if `BreakageRequired` is not checked first,
/// this test would observe `SetIdExecution` instead, the wrong
/// variant. Proven identically for BOTH entry points — `gran mount`
/// (`parse_mount`) and `mount.gran` (`parse_mount_gran`) — since
/// both converge on this one function and neither parser can arm
/// `breakage` for these invocations (the arming vocabulary is `gran
/// mount --breakage <name>` alone).
#[cfg(feature = "conformance-breakage")]
#[test]
fn mount_attempt_with_credentials_refuses_missing_breakage_before_set_id_and_regardless_of_entry_point()
 {
    let key = root_key_str();
    let tainted = ProcessCredentials {
        ruid: 1_000,
        euid: 1_001,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    };

    let native_args = mount_argv(&["--root-key", &key]);
    let margs_native = parse_mount(&native_args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(margs_native.breakage, None, "fixture precondition: unarmed");
    assert!(
        matches!(
            mount_attempt_with_credentials(
                &margs_native,
                &tainted,
                &mut Vec::new(),
                &crate::terminal::write_line
            ),
            Err(MountRefusal::BreakageRequired)
        ),
        "missing --breakage must be refused before set-ID execution, from parse_mount"
    );

    let gran_args: Vec<OsString> = [
        "vol",
        "/mnt",
        "-o",
        &format!("endpoint=https://h,pin={},root_key={key}", a_pin()),
    ]
    .iter()
    .map(|s| osstr(s))
    .collect();
    let margs_gran = parse_mount_gran(&gran_args).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(margs_gran.breakage, None, "fixture precondition: unarmed");
    assert!(
        matches!(
            mount_attempt_with_credentials(
                &margs_gran,
                &tainted,
                &mut Vec::new(),
                &crate::terminal::write_line
            ),
            Err(MountRefusal::BreakageRequired)
        ),
        "missing --breakage must be refused identically from parse_mount_gran"
    );
}

// ------------------------------------------------ Set-ID refusal

/// A set-ID (`ruid != euid`) invocation must be
/// refused as [`MountRefusal::SetIdExecution`] — and this must be
/// the FIRST thing `mount_attempt_with_credentials` checks, before
/// even the foreground gate: `margs` here has no `--foreground`, so
/// if the set-ID check were not first, `mount_requires_foreground`
/// would refuse first instead, with the WRONG variant. Matching,
/// untainted credentials on the identical `margs` must NOT be
/// refused as set-ID execution — it still fails, for the unrelated
/// (foreground) reason, which is asserted by variant, not by
/// `is_err()` alone.
#[test]
fn mount_attempt_with_credentials_refuses_set_id_execution_first() {
    let key = root_key_str();
    #[cfg(not(feature = "conformance-breakage"))]
    let args = mount_argv(&["--root-key", &key]);
    // This test's own subject is the set-ID gate, which sits AFTER
    // the breakage-required gate — arm it
    // explicitly so the set-ID gate is what actually fires, the
    // same way the SEPARATE `mount_attempt_with_credentials_
    // refuses_missing_breakage_...` test proves the breakage gate
    // itself, ahead of this one.
    #[cfg(feature = "conformance-breakage")]
    let args = mount_argv(&[
        "--root-key",
        &key,
        "--breakage",
        granary_fuse::Breakage::TruncateRead.name(),
    ]);
    let margs = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));
    assert!(!margs.foreground, "fixture precondition: no --foreground");

    let tainted = ProcessCredentials {
        ruid: 1_000,
        euid: 1_001,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    };
    assert!(
        matches!(
            mount_attempt_with_credentials(
                &margs,
                &tainted,
                &mut Vec::new(),
                &crate::terminal::write_line
            ),
            Err(MountRefusal::SetIdExecution)
        ),
        "a set-ID (ruid != euid) invocation must be refused before any other gate, \
         including the foreground gate this margs would otherwise hit first"
    );

    let matching = ProcessCredentials {
        ruid: 1_000,
        euid: 1_000,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: false,
    };
    match mount_attempt_with_credentials(
        &margs,
        &matching,
        &mut Vec::new(),
        &crate::terminal::write_line,
    ) {
        Err(MountRefusal::SetIdExecution) => {
            panic!("matching, untainted credentials must not be refused as set-ID execution")
        }
        Err(MountRefusal::Foreground) => {}
        other => panic!(
            "expected Err(MountRefusal::Foreground) (no --foreground was given), got \
             {other:?}"
        ),
    }
}

/// The platform taint probe alone — matching visible
/// ids, `set_id_tainted: true` — must ALSO be refused as
/// [`MountRefusal::SetIdExecution`], so the taint arm of
/// `set_id_refusal` is exercised through this call site too, not
/// just the id-mismatch arm the test above covers.
#[test]
fn mount_attempt_with_credentials_refuses_set_id_taint_alone() {
    let key = root_key_str();
    #[cfg(not(feature = "conformance-breakage"))]
    let args = mount_argv(&["--root-key", &key]);
    // See the identical note in the sibling test just above.
    #[cfg(feature = "conformance-breakage")]
    let args = mount_argv(&[
        "--root-key",
        &key,
        "--breakage",
        granary_fuse::Breakage::TruncateRead.name(),
    ]);
    let margs = parse_mount(&args).unwrap_or_else(|e| panic!("{e}"));

    let tainted = ProcessCredentials {
        ruid: 1_000,
        euid: 1_000,
        rgid: 2_000,
        egid: 2_000,
        set_id_tainted: true,
    };
    assert!(
        matches!(
            mount_attempt_with_credentials(
                &margs,
                &tainted,
                &mut Vec::new(),
                &crate::terminal::write_line
            ),
            Err(MountRefusal::SetIdExecution)
        ),
        "the platform set-ID taint probe alone (matching visible ids) must also be refused"
    );
}

/// The pre-flight call must be proved directly. Before this
/// test, `mount_preflight` was thoroughly unit-tested but NOTHING
/// proved `cmd_mount` ever CALLED it: a mutation
/// replaced the call with `let _ = (...)` and the whole suite,
/// including `cmd_mount_refuses_backgrounding_before_touching_
/// anything_else` above, stayed green — that test's own exit code
/// cannot tell "pre-flight refused" from any of the other nine
/// early returns sharing `RuntimeFailure`. The typed
/// [`MountRefusal`] is what makes this decisive: matching the
/// SPECIFIC `Preflight` variant proves the call happened, not just
/// that SOMETHING refused before the daemon.
///
/// **No `--cache-dir` is given.** Preflight fires strictly before
/// the cache-dir gate (`mount_attempt_with_credentials`'s own
/// order); if the mutation above were reintroduced, this would
/// observe `Err(MountRefusal::CacheDirRequired)` instead — a
/// DIFFERENT variant — never `Preflight`, which is exactly the
/// discriminating power this test exists for.
#[test]
fn mount_attempt_calls_preflight_and_reports_which_refusal_fired() {
    let dir = MountScratchDir::new();
    // Non-empty on every platform this repo targets: on Linux,
    // `refuse_if_already_mounted`'s real /proc check passes for a
    // fresh scratch dir, so `refuse_if_nonempty` is what actually
    // refuses — a NotEmpty entry proves this test still reaches
    // pre-flight's SECOND check there, not just its first.
    std::fs::write(dir.0.join("occupant"), b"x").unwrap_or_else(|e| panic!("{e}"));
    let key = root_key_str();
    // This test's own subject is the pre-flight gate, which sits
    // AFTER the breakage-required gate — arm
    // it explicitly on every `mount_argv_at` call in this test so
    // pre-flight is what actually fires.
    #[cfg(not(feature = "conformance-breakage"))]
    let argv = mount_argv_at(&dir.0, &["--root-key", &key, "--foreground"]);
    #[cfg(feature = "conformance-breakage")]
    let argv = mount_argv_at(
        &dir.0,
        &[
            "--root-key",
            &key,
            "--foreground",
            "--breakage",
            granary_fuse::Breakage::TruncateRead.name(),
        ],
    );
    let margs = parse_mount(&argv).unwrap_or_else(|e| panic!("{e}"));
    let credentials = process_credentials();
    match mount_attempt_with_credentials(
        &margs,
        &credentials,
        &mut Vec::new(),
        &crate::terminal::write_line,
    ) {
        Err(MountRefusal::Preflight(_)) => {}
        other => panic!(
            "expected mount_attempt_with_credentials to call mount_preflight and report its \
             refusal, got {other:?} — Err(MountRefusal::CacheDirRequired) here would mean \
             pre-flight was skipped entirely"
        ),
    }

    // `--force`: force skips ONLY the
    // non-empty check, never the already-mounted one.
    #[cfg(not(feature = "conformance-breakage"))]
    let argv_forced = mount_argv_at(&dir.0, &["--root-key", &key, "--foreground", "--force"]);
    #[cfg(feature = "conformance-breakage")]
    let argv_forced = mount_argv_at(
        &dir.0,
        &[
            "--root-key",
            &key,
            "--foreground",
            "--force",
            "--breakage",
            granary_fuse::Breakage::TruncateRead.name(),
        ],
    );
    let margs_forced = parse_mount(&argv_forced).unwrap_or_else(|e| panic!("{e}"));
    if cfg!(target_os = "linux") {
        // The already-mounted check passes for real (this scratch
        // dir is not a mount point), so force gets mount_preflight
        // all the way to Ok — proving force genuinely reaches a
        // DIFFERENT refusal one gate later:
        // `MountRefusal::CacheDirRequired`.
        assert!(
            matches!(
                mount_attempt_with_credentials(
                    &margs_forced,
                    &credentials,
                    &mut Vec::new(),
                    &crate::terminal::write_line
                ),
                Err(MountRefusal::CacheDirRequired)
            ),
            "on Linux, --force must get past pre-flight to the NEXT gate (no --cache-dir \
             was given)"
        );
    } else {
        // `refuse_if_already_mounted`'s non-Linux arm
        // (`MountPreflightError::MountCheckUnsupported`) runs
        // UNCONDITIONALLY, before the force-gated non-empty check —
        // mount_preflight's own doc and
        // `mount_preflight_names_the_platform_when_the_mount_check_
        // is_unsupported` already establish this. So on THIS box
        // `--force` cannot be observed changing the outcome: both
        // calls refuse at the identical gate. This checks the
        // platform's unconditional refusal; it cannot establish
        // how `--force` affects the later non-empty check.
        match mount_attempt_with_credentials(
            &margs_forced,
            &credentials,
            &mut Vec::new(),
            &crate::terminal::write_line,
        ) {
            Err(MountRefusal::Preflight(MountPreflightError::MountCheckUnsupported { os })) => {
                assert_eq!(os, std::env::consts::OS);
            }
            other => {
                panic!("expected the identical MountCheckUnsupported refusal, got {other:?}")
            }
        }
    }
}

/// The WIRING half of the pre-flight proof, on `cmd_mount_refuses_backgrounding_
/// before_touching_anything_else`'s own precedent: proves `cmd_mount`
/// itself (not just `mount_attempt_with_credentials`) reaches
/// pre-flight and maps its refusal to the pinned exit code. The
/// DECISIVE assertion — which refusal specifically — is
/// `mount_attempt_calls_preflight_and_reports_which_refusal_fired`
/// above; this one alone could not tell a skipped pre-flight from
/// any other early `RuntimeFailure`.
#[test]
fn cmd_mount_refuses_a_nonempty_existing_mountpoint_via_preflight() {
    let dir = MountScratchDir::new();
    std::fs::write(dir.0.join("occupant"), b"x").unwrap_or_else(|e| panic!("{e}"));
    let key = root_key_str();
    // This test's subject is the pre-flight
    // gate, which sits AFTER the breakage-required gate — arm it
    // explicitly, same reasoning as its sibling above.
    #[cfg(not(feature = "conformance-breakage"))]
    let argv = mount_argv_at(&dir.0, &["--root-key", &key, "--foreground"]);
    #[cfg(feature = "conformance-breakage")]
    let argv = mount_argv_at(
        &dir.0,
        &[
            "--root-key",
            &key,
            "--foreground",
            "--breakage",
            granary_fuse::Breakage::TruncateRead.name(),
        ],
    );
    let margs = parse_mount(&argv).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        cmd_mount(&margs, &mut Vec::new()),
        mount_exit_code(MountOutcome::RuntimeFailure)
    );
}

/// A coordinator's calls in order, shared with the closures that make them.
#[derive(Clone, Default)]
struct Calls(std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>);

impl Calls {
    fn push(&self, call: &'static str) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(call);
    }
    fn taken(&self) -> Vec<&'static str> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    fn count(&self, call: &str) -> usize {
        self.taken().iter().filter(|made| **made == call).count()
    }
}

/// No engine to stop: a read-only mount.
type NoEngine = EngineStop<fn(granary_client::ShutdownTrigger) -> std::io::Result<()>, fn()>;

/// A grace long enough that a row ending inside it did not wait it out.
const LONG_GRACE: std::time::Duration = std::time::Duration::from_mins(1);
/// A grace a row waits out.
const SHORT_GRACE: std::time::Duration = std::time::Duration::from_millis(50);

/// An engine whose `start` records itself and, given an answer, sends it as
/// the shutdown thread's `Outcome`; `expire` records itself.
fn answering(
    calls: &Calls,
    tx: &std::sync::mpsc::Sender<Exit>,
    answer: Option<granary_client::ShutdownReport>,
) -> EngineStop<impl FnOnce(granary_client::ShutdownTrigger) -> std::io::Result<()>, impl Fn()> {
    let (started, expired, tx) = (calls.clone(), calls.clone(), tx.clone());
    EngineStop {
        start: move |_| {
            started.push("start");
            if let Some(answer) = answer {
                let _ = tx.send(Exit::Outcome(answer));
            }
            Ok(())
        },
        expire: move || expired.push("expire"),
    }
}

/// An unmount that records itself and then sends `then` on `tx`, as the
/// kernel does once the session it ends has run `destroy`.
fn unmounting(
    calls: &Calls,
    tx: &std::sync::mpsc::Sender<Exit>,
    then: Vec<Exit>,
) -> impl FnOnce() -> std::io::Result<()> {
    let (calls, tx) = (calls.clone(), tx.clone());
    move || {
        calls.push("unmount");
        for message in then {
            let _ = tx.send(message);
        }
        Ok(())
    }
}

/// A signal runs the engine's shutdown BEFORE the unmount, and its outcome
/// is held from the message, not from the join; the join follows the
/// session end the unmount brings. Unmounting first, as a read-only mount
/// does, puts the unmount ahead of the start.
#[test]
fn coordinator_runs_the_shutdown_before_the_unmount() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    let calls = Calls::default();
    let joins = calls.clone();
    let coordinated = run_coordinator(
        &rx,
        None,
        Some(answering(&calls, &tx, Some(committed()))),
        unmounting(&calls, &tx, vec![Exit::SessionEnded]),
        || unreachable!("the plain unmount succeeded"),
        move || joins.push("join"),
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (
            calls.taken(),
            coordinated.report,
            coordinated.joined.is_some()
        ),
        (vec!["start", "unmount", "join"], Some(committed()), true),
        "(calls, report, joined)"
    );
}

/// Every signal after the first expires the running shutdown, before any
/// unmount: the fake answers only once it has been expired twice (or, so a
/// mutant cannot hang the row, after ten seconds). Ignoring a later signal
/// leaves the outcome to the fallback and the expiries uncounted.
#[test]
fn coordinator_expires_on_each_later_signal() {
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..3 {
        tx.send(Exit::Signal("SIGTERM")).unwrap();
    }
    let calls = Calls::default();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let (started, expired, answer_tx) = (calls.clone(), calls.clone(), tx.clone());
    let release = std::sync::Mutex::new(Some(release));
    let stop = EngineStop {
        start: move |_| {
            started.push("start");
            std::thread::spawn(move || {
                let _ = released.recv_timeout(std::time::Duration::from_secs(10));
                let _ = answer_tx.send(Exit::Outcome(committed()));
            });
            Ok(())
        },
        expire: move || {
            expired.push("expire");
            if expired.count("expire") == 2 {
                drop(release.lock().unwrap().take());
            }
        },
    };
    let joins = calls.clone();
    let coordinated = run_coordinator(
        &rx,
        None,
        Some(stop),
        unmounting(&calls, &tx, vec![Exit::SessionEnded]),
        || unreachable!("the plain unmount succeeded"),
        move || joins.push("join"),
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (calls.taken(), coordinated.signals, coordinated.report),
        (
            vec!["start", "expire", "expire", "unmount", "join"],
            3,
            Some(committed())
        ),
        "(calls, signals, report)"
    );
}

/// A signal's shutdown meets a session end that the kernel delivers while
/// it runs: after the first signal and a second one, the teardown notice,
/// the outcome and the session end arrive in each of their six orders. In
/// every order the shutdown starts once and is expired once, the unmount
/// runs once, and the session is joined. Starting again on a later signal
/// starts twice.
#[test]
fn coordinator_signal_during_a_session_end_sequence() {
    let orders: [[usize; 3]; 6] = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut cases = 0;
    for order in orders {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Exit::Signal("SIGTERM")).unwrap();
        tx.send(Exit::Signal("SIGINT")).unwrap();
        let messages = [
            Exit::Teardown,
            Exit::Outcome(committed()),
            Exit::SessionEnded,
        ];
        for index in order {
            tx.send(messages[index]).unwrap();
        }
        let calls = Calls::default();
        let joins = calls.clone();
        let coordinated = run_coordinator(
            &rx,
            None,
            Some(answering(&calls, &tx, None)),
            unmounting(&calls, &tx, vec![]),
            || unreachable!("the plain unmount succeeded"),
            move || joins.push("join"),
            LONG_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        assert_eq!(
            (
                calls.count("start"),
                calls.count("expire"),
                calls.count("unmount"),
                coordinated.joined.is_some(),
                coordinated.report,
            ),
            (1, 1, 1, true, Some(committed())),
            "order {order:?}: (starts, expiries, unmounts, joined, report)"
        );
        cases += 1;
    }
    assert_eq!(cases, 6);
}

/// After a successful unmount the join waits for the session end on the
/// channel, never blindly: with none, the coordinator returns once its grace
/// has run out, without joining; with one, it joins. A join after every
/// successful unmount hangs a daemon whose descriptor is held.
#[test]
fn coordinator_waits_for_session_end_on_the_channel() {
    let mut rows = Vec::new();
    for ended in [false, true] {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Exit::Signal("SIGTERM")).unwrap();
        let calls = Calls::default();
        let joins = calls.clone();
        let then = if ended {
            vec![Exit::SessionEnded]
        } else {
            vec![]
        };
        let coordinated = run_coordinator(
            &rx,
            None,
            None::<NoEngine>,
            unmounting(&calls, &tx, then),
            || unreachable!("the plain unmount succeeded"),
            move || joins.push("join"),
            SHORT_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        rows.push((ended, calls.count("join"), coordinated.joined.is_some()));
    }
    assert_eq!(
        rows,
        vec![(false, 0, false), (true, 1, true)],
        "(session ended, joins, joined)"
    );
}

/// The teardown notice lifts the grace: a session end that comes three
/// graces after it is still joined, because the wait is now for `destroy`.
#[test]
fn coordinator_teardown_lifts_the_grace() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    let calls = Calls::default();
    let joins = calls.clone();
    let late = tx.clone();
    let unmount = move || {
        let _ = late.send(Exit::Teardown);
        std::thread::spawn(move || {
            pause(SHORT_GRACE * 3);
            let _ = late.send(Exit::SessionEnded);
        });
        Ok(())
    };
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        unmount,
        || unreachable!("the plain unmount succeeded"),
        move || joins.push("join"),
        SHORT_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (coordinated.teardown_seen, coordinated.joined.is_some()),
        (true, true),
        "(teardown seen, joined)"
    );
}

/// A signal while draining, with the shutdown's report already in hand,
/// ends the wait at once, teardown or not, and expires nothing: there is no
/// sequence left to cut. The signal is sent only once the unmount has run
/// and the teardown notice is in, so the coordinator is in its untimed
/// drain wait, and it returns well inside the grace.
#[test]
fn coordinator_signal_during_drain_stops_waiting() {
    let calls = Calls::default();
    let coordinator_calls = calls.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    let (unmounted, drained) = std::sync::mpsc::channel();
    let (answered, answer) = std::sync::mpsc::channel();
    let coordinator_tx = tx.clone();
    // On its own thread, so a coordinator that kept waiting fails the row
    // at its bound instead of hanging it.
    std::thread::spawn(move || {
        let joins = coordinator_calls.clone();
        let unmount = unmounting(&coordinator_calls, &coordinator_tx, vec![Exit::Teardown]);
        let coordinated = run_coordinator(
            &rx,
            None,
            Some(answering(
                &coordinator_calls,
                &coordinator_tx,
                Some(committed()),
            )),
            move || {
                let result = unmount();
                let _ = unmounted.send(());
                result
            },
            || unreachable!("the plain unmount succeeded"),
            move || joins.push("join"),
            LONG_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        let _ = answered.send((coordinated.joined.is_some(), coordinated.signals));
    });
    drained
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap();
    // The coordinator reads the teardown notice and parks in its wait.
    pause(SHORT_GRACE * 4);
    let parked = answer.try_recv().is_err();
    tx.send(Exit::Signal("SIGINT")).unwrap();
    assert_eq!(
        (
            parked,
            answer.recv_timeout(std::time::Duration::from_secs(2)).ok(),
            calls.count("expire"),
        ),
        (true, Some((false, 2)), 0),
        "(still waiting before the signal, (joined, signals) within 2 s of a 60 s grace, \
         expiries)"
    );
}

/// With no shutdown thread, a signal while draining after the teardown
/// notice expires `destroy`'s sequence and the wait goes on; a further
/// signal ends the wait for `destroy`'s cache close, without a join.
#[test]
fn coordinator_a_further_signal_ends_the_wait_for_destroy() {
    let calls = Calls::default();
    let coordinator_calls = calls.clone();
    let (answered, answer) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Exit::Signal("SIGTERM")).unwrap();
        let (started, expired) = (coordinator_calls.clone(), coordinator_calls.clone());
        let joins = coordinator_calls.clone();
        let coordinated = run_coordinator(
            &rx,
            None,
            Some(EngineStop {
                start: move |_| {
                    started.push("start");
                    Err(std::io::Error::other("no thread"))
                },
                expire: move || expired.push("expire"),
            }),
            unmounting(
                &coordinator_calls,
                &tx,
                vec![
                    Exit::Teardown,
                    Exit::Signal("SIGINT"),
                    Exit::Signal("SIGTERM"),
                ],
            ),
            || unreachable!("the plain unmount succeeded"),
            move || joins.push("join"),
            LONG_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        let _ = answered.send((coordinated.joined.is_some(), coordinated.signals));
    });
    assert_eq!(
        (
            answer.recv_timeout(std::time::Duration::from_secs(10)).ok(),
            calls.taken(),
        ),
        (Some((false, 3)), vec!["start", "unmount", "expire"]),
        "((joined, signals), calls)"
    );
}

/// With no shutdown thread (its spawn failed), the sequence is `destroy`'s:
/// a signal while draining expires it, and once the teardown notice says it
/// is running the wait goes on to the session end, which is joined. Without
/// the notice no sequence runs, so the signal expires the one that has not
/// begun and ends the wait.
#[test]
fn coordinator_expires_a_destroy_path_sequence() {
    let mut rows = Vec::new();
    for teardown in [true, false] {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Exit::Signal("SIGTERM")).unwrap();
        let calls = Calls::default();
        let (started, expired, ended) = (calls.clone(), calls.clone(), tx.clone());
        let stop = EngineStop {
            start: move |_| {
                started.push("start");
                Err(std::io::Error::other("no thread"))
            },
            expire: move || {
                expired.push("expire");
                if teardown {
                    // The cut sequence answers and the session ends.
                    let _ = ended.send(Exit::SessionEnded);
                }
            },
        };
        let mut then = vec![Exit::Signal("SIGINT")];
        if teardown {
            then.insert(0, Exit::Teardown);
        }
        let joins = calls.clone();
        let coordinated = run_coordinator(
            &rx,
            None,
            Some(stop),
            unmounting(&calls, &tx, then),
            || unreachable!("the plain unmount succeeded"),
            move || joins.push("join"),
            LONG_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        rows.push((
            teardown,
            calls.taken(),
            coordinated.joined.is_some(),
            coordinated.report,
        ));
    }
    assert_eq!(
        rows,
        vec![
            (true, vec!["start", "unmount", "expire", "join"], true, None),
            (false, vec!["start", "unmount", "expire"], false, None),
        ],
        "(teardown, calls, joined, report)"
    );
}

/// A busy root mount: the unmount answers `EBUSY`, the detach takes the
/// mount out of the table, and no session end comes within the grace. The
/// outcome the shutdown answered before the unmount is kept, and with the
/// mount gone the daemon exits 3: the cache close never ran. With the
/// detach failed and the mount still listed it exits 1.
#[test]
fn coordinator_ebusy_keeps_the_outcome() {
    let mut rows = Vec::new();
    for detached in [true, false] {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Exit::Signal("SIGTERM")).unwrap();
        let calls = Calls::default();
        let coordinated = run_coordinator(
            &rx,
            None,
            Some(answering(&calls, &tx, Some(committed()))),
            || Err(std::io::Error::from_raw_os_error(libc::EBUSY)),
            || {
                if detached {
                    Ok(())
                } else {
                    Err(granary_client::FailureClass::Io)
                }
            },
            || unreachable!("no session end came"),
            SHORT_GRACE,
            || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
        );
        let joined: Option<std::thread::Result<std::io::Result<()>>> =
            coordinated.joined.map(|()| Ok(Ok(())));
        let session = session_verdict(
            unmount_evidence(coordinated.arm, coordinated.unmount, coordinated.detach),
            joined,
            || Ok(!detached),
            || None,
        );
        rows.push((
            detached,
            coordinated.report,
            mount_shutdown_outcome(coordinated.report, true, &session, None),
        ));
    }
    assert_eq!(
        rows,
        vec![
            (true, Some(committed()), MountOutcome::CacheCloseFailed),
            (false, Some(committed()), MountOutcome::RuntimeFailure),
        ],
        "(detached, report, exit)"
    );
}

/// A writable engine's shutdown, as the daemon drives it, for the rows
/// that need one: it answers `answer`, or panics, and holds its report as
/// the handle does once a sequence has ended.
struct FakeStop {
    answer: granary_client::ShutdownReport,
    panics: bool,
    began: std::sync::atomic::AtomicUsize,
    done: std::sync::Mutex<Option<granary_client::ShutdownReport>>,
}

impl FakeStop {
    fn answering(answer: granary_client::ShutdownReport) -> Self {
        Self {
            answer,
            panics: false,
            began: std::sync::atomic::AtomicUsize::new(0),
            done: std::sync::Mutex::new(None),
        }
    }
}

impl DaemonStop for FakeStop {
    fn begin(&self, _trigger: granary_client::ShutdownTrigger) -> granary_client::ShutdownReport {
        self.began.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert!(
            !self.panics,
            "simulated shutdown panic, for the outcome guard's own test"
        );
        *self.done.lock().unwrap() = Some(self.answer);
        self.answer
    }
    fn expire(&self) {}
    fn report(&self) -> Option<granary_client::ShutdownReport> {
        *self.done.lock().unwrap()
    }
}

/// A shutdown thread that cannot be spawned sends the coordinator straight
/// to the unmount with no report; the session end follows, and the report
/// is then read from the handle, which `destroy` has run on the session-end
/// path.
#[test]
fn coordinator_spawn_failure_falls_back() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    let calls = Calls::default();
    let started = calls.clone();
    let joins = calls.clone();
    let coordinated = run_coordinator(
        &rx,
        None,
        Some(EngineStop {
            start: move |_| {
                started.push("start");
                Err(std::io::Error::other("no thread"))
            },
            expire: || unreachable!("no further signal"),
        }),
        unmounting(&calls, &tx, vec![Exit::Teardown, Exit::SessionEnded]),
        || unreachable!("the plain unmount succeeded"),
        move || joins.push("join"),
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    let handle = FakeStop::answering(committed());
    *handle.done.lock().unwrap() = Some(committed());
    assert_eq!(
        (
            calls.taken(),
            coordinated.report,
            shutdown_report(coordinated.report, Some(&handle)),
            shutdown_report(
                Some(report_of(granary_client::ShutdownOutcome::Clean)),
                Some(&handle)
            ),
        ),
        (
            vec!["start", "unmount", "join"],
            None,
            Some(committed()),
            Some(report_of(granary_client::ShutdownOutcome::Clean)),
        ),
        "(calls, the coordinator's report, the report read after, a message outranking the handle)"
    );
}

/// Each shutdown thread sends exactly one `Outcome`, on real threads: a
/// `begin` that returns sends its report and nothing more, and one that
/// panics sends one lost report; either way the channel then disconnects,
/// so nothing else follows. A guard that also sent on every drop sends a
/// second outcome after the real one; no guard sends nothing on a panic.
#[test]
fn outcome_guard_sends_exactly_one_outcome() {
    let mut rows = Vec::new();
    for panics in [false, true] {
        let (tx, rx) = std::sync::mpsc::channel();
        let stop = std::sync::Arc::new(FakeStop {
            panics,
            ..FakeStop::answering(committed())
        });
        start_shutdown(stop.clone(), tx, granary_client::ShutdownTrigger::Signal).unwrap();
        let first = rx.recv_timeout(std::time::Duration::from_secs(20));
        let then = rx.recv_timeout(std::time::Duration::from_secs(20));
        rows.push((panics, first, then));
    }
    assert_eq!(
        rows,
        vec![
            (
                false,
                Ok(Exit::Outcome(committed())),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
            ),
            (
                true,
                Ok(Exit::Outcome(granary_client::ShutdownReport::lost())),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
            ),
        ],
        "(begin panics, first message, what follows)"
    );
}

/// A scripted signal stream of three deliveries, then its end: each is
/// sent, in order, and the count says so. A coordinator that is gone stops
/// the forwarding at the first delivery. Forwarding only the first sends
/// one.
/// A signal stream that delivers `deliveries` times, then ends, counting
/// its polls in `polls`.
fn scripted(
    deliveries: usize,
    polls: &std::sync::atomic::AtomicUsize,
) -> impl FnMut(&mut std::task::Context<'_>) -> std::task::Poll<Option<()>> + '_ {
    move |_| {
        let polled = polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        std::task::Poll::Ready((polled < deliveries).then_some(()))
    }
}

#[test]
fn forward_signals_sends_every_delivery() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let polls = std::sync::atomic::AtomicUsize::new(0);
    let (tx, rx) = std::sync::mpsc::channel();
    let sent = runtime.block_on(forward_signals(scripted(3, &polls), tx, "SIGTERM"));
    let received: Vec<Exit> = rx.try_iter().collect();
    let gone_polls = std::sync::atomic::AtomicUsize::new(0);
    let (tx, rx) = std::sync::mpsc::channel();
    drop(rx);
    let gone = runtime.block_on(forward_signals(
        scripted(usize::MAX, &gone_polls),
        tx,
        "SIGINT",
    ));
    assert_eq!(
        (
            sent,
            received,
            polls.into_inner(),
            gone,
            gone_polls.into_inner()
        ),
        (3, vec![Exit::Signal("SIGTERM"); 3], 4, 0, 1),
        "(sent, received, polls, sent with the coordinator gone, its polls)"
    );
}

/// With no engine and only a signal, the unmount runs before the join, and
/// the join follows the session end the unmount brings, never the unmount
/// itself. `detach` does not run: the plain unmount succeeded.
#[test]
fn coordinator_unmounts_before_it_joins() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    let calls = Calls::default();
    let joins = calls.clone();
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        unmounting(&calls, &tx, vec![Exit::SessionEnded]),
        || unreachable!("detach must not run when the plain unmount already succeeded"),
        move || joins.push("join"),
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (
            coordinated.arm,
            coordinated.unmount.is_ok(),
            coordinated.detach.is_none(),
            calls.taken(),
        ),
        (Exit::Signal("SIGTERM"), true, true, vec!["unmount", "join"]),
        "(arm, unmounted, detach not run, calls)"
    );
}

/// **Termination that needs no signal producer**: a topology where ONLY the
/// session-ended producer ever sends — exactly what an external `gran
/// umount` looks like from the coordinator's side — still unmounts (an
/// idempotent call) and joins at once, needing no grace. A coordinator that
/// waited on a signal-shaped arm specifically would hang here instead.
#[test]
fn coordinator_terminates_on_session_ended_alone_no_signal_ever_sent() {
    let (tx, rx) = std::sync::mpsc::channel();
    let sender = std::thread::spawn(move || {
        tx.send(Exit::SessionEnded)
            .unwrap_or_else(|e| panic!("{e}"));
    });
    sender
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        || Ok(()),
        || unreachable!("detach must not run when the plain unmount already succeeded"),
        || 42,
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(coordinated.arm, Exit::SessionEnded);
    assert!(coordinated.unmount.is_ok());
    assert!(coordinated.detach.is_none(), "detach must not have run");
    assert_eq!(coordinated.joined, Some(42));
}

/// A failed unmount with no session end never joins: the session thread may
/// be serving a held descriptor, and joining it is what would hang the
/// coordinator. The unmount's error survives in the returned value.
#[test]
fn coordinator_does_not_join_when_unmount_fails() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGINT"))
        .unwrap_or_else(|e| panic!("{e}"));
    let join_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let join_called_inner = std::sync::Arc::clone(&join_called);
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        || Err(std::io::Error::other("EBUSY")),
        || Ok(()),
        || {
            join_called_inner.store(true, std::sync::atomic::Ordering::SeqCst);
            7
        },
        SHORT_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(coordinated.arm, Exit::Signal("SIGINT"));
    assert!(
        coordinated.unmount.is_err(),
        "the unmount error must reach the caller, not be silently discarded"
    );
    assert!(
        !join_called.load(std::sync::atomic::Ordering::SeqCst),
        "join must not run with no session end"
    );
    assert_eq!(coordinated.joined, None);
}

/// `unmount` succeeding must skip `detach` ENTIRELY — no call at all, not
/// merely a call whose result is discarded — and still join. The
/// `unreachable!` in the closure makes "call `detach` unconditionally" a
/// real panic, not a silent pass.
#[test]
fn coordinator_never_calls_detach_when_unmount_succeeds() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::SessionEnded)
        .unwrap_or_else(|e| panic!("{e}"));
    let join_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let join_called_inner = std::sync::Arc::clone(&join_called);
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        || Ok(()),
        || unreachable!("detach must never be called when the plain unmount succeeded"),
        || {
            join_called_inner.store(true, std::sync::atomic::Ordering::SeqCst);
        },
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert!(coordinated.unmount.is_ok());
    assert!(coordinated.detach.is_none());
    assert!(join_called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(coordinated.joined, Some(()));
}

/// A failed plain `unmount` falls back to `detach` — called for real — and a
/// successful detach does not bring the join back: the connection can
/// outlive a successful `MNT_DETACH` while a file on it stays open, so only
/// a session end permits the join.
#[test]
fn coordinator_calls_detach_and_still_skips_join_when_unmount_fails() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM"))
        .unwrap_or_else(|e| panic!("{e}"));
    let detach_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let detach_called_inner = std::sync::Arc::clone(&detach_called);
    let join_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let join_called_inner = std::sync::Arc::clone(&join_called);
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        || Err(std::io::Error::other("EBUSY")),
        move || {
            detach_called_inner.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
        || {
            join_called_inner.store(true, std::sync::atomic::Ordering::SeqCst);
        },
        SHORT_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert!(coordinated.unmount.is_err());
    assert!(detach_called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(coordinated.detach, Some(Ok(())));
    assert!(!join_called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(coordinated.joined, None);
}

/// When BOTH the plain unmount and the `MNT_DETACH` fallback fail, both
/// failures survive in the returned value, and with no session end there is
/// no join.
#[test]
fn coordinator_reports_both_unmount_and_detach_failures() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM"))
        .unwrap_or_else(|e| panic!("{e}"));
    let coordinated = run_coordinator(
        &rx,
        None,
        None::<NoEngine>,
        || Err(std::io::Error::other("EBUSY")),
        || Err(granary_client::FailureClass::Refused),
        || unreachable!("no session end came"),
        SHORT_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert!(coordinated.unmount.is_err());
    assert_eq!(
        coordinated.detach,
        Some(Err(granary_client::FailureClass::Refused))
    );
    assert_eq!(coordinated.joined, None);
}

/// Two signals queued before the coordinator reads either: the first is
/// the arm and starts the shutdown, the second expires it, and the start's
/// outcome, queued behind both, is the report. A coordinator that drained
/// to the last message, or started on each, fails the calls.
#[test]
fn coordinator_starts_on_the_first_of_two_queued_signals_and_the_second_expires() {
    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(Exit::Signal("SIGTERM")).unwrap();
    tx.send(Exit::Signal("SIGINT")).unwrap();
    let calls = Calls::default();
    let joins = calls.clone();
    let coordinated = run_coordinator(
        &rx,
        None,
        Some(answering(&calls, &tx, Some(committed()))),
        unmounting(&calls, &tx, vec![Exit::SessionEnded]),
        || unreachable!("the plain unmount succeeded"),
        move || joins.push("join"),
        LONG_GRACE,
        || granary_client::SyncRuntime::now(&granary_client::TokioSyncRuntime),
    );
    assert_eq!(
        (coordinated.arm, calls.taken(), coordinated.report),
        (
            Exit::Signal("SIGTERM"),
            vec!["start", "expire", "unmount", "join"],
            Some(committed())
        ),
        "(arm, calls, report)"
    );
}

// ------------------------------------------------- MOUNT_HELP content

#[test]
fn mount_help_states_trust_mode_is_required_and_why() {
    assert!(MOUNT_HELP.contains("REQUIRED"));
    assert!(MOUNT_HELP.contains("long-lived and ambient"));
    assert!(MOUNT_HELP.contains("silently"));
}

#[test]
fn mount_help_states_reset_floor_is_discouraged_and_why() {
    assert!(MOUNT_HELP.contains("--reset-floor is DISCOURAGED"));
    assert!(MOUNT_HELP.contains("anchors/<volume>.mount"));
    assert!(MOUNT_HELP.contains("re-poison"));
}

/// The signature line and the prose must agree that
/// `--cache-dir` is required, not bracketed as optional the way
/// `cmd_mount`'s own real refusal (`mount_argv`'s sibling tests
/// exercise it) already treats it.
#[test]
fn mount_help_states_cache_dir_is_required_and_why() {
    assert!(MOUNT_HELP.contains("--cache-dir <path> is REQUIRED"));
    assert!(!MOUNT_HELP.contains("[--cache-dir"));
    assert!(MOUNT_HELP.contains("whole read path"));
}

/// The help must require `--foreground` and explain that
/// backgrounding is not implemented.
#[test]
fn mount_help_states_foreground_is_required_and_why() {
    assert!(MOUNT_HELP.contains("--foreground is REQUIRED"));
    assert!(!MOUNT_HELP.contains("[--foreground]"));
    assert!(MOUNT_HELP.contains("backgrounding") && MOUNT_HELP.contains("is not implemented"));
}

#[test]
fn mount_help_states_the_allow_other_security_consequence() {
    assert!(MOUNT_HELP.contains("every local user"));
    assert!(MOUNT_HELP.contains("read"));
    assert!(MOUNT_HELP.contains("signed exec"));
    assert!(MOUNT_HELP.contains("own credentials"));
}

#[test]
fn mount_help_states_the_exit_codes() {
    assert!(MOUNT_HELP.contains("0 clean"));
    assert!(MOUNT_HELP.contains("1 runtime failure"));
    assert!(MOUNT_HELP.contains("2 usage error"));
    assert!(MOUNT_HELP.contains("3 unmounted"));
    assert!(MOUNT_HELP.contains("cache could not be closed cleanly"));
    assert!(MOUNT_HELP.contains("4 shutdown stopped, everything kept"));
    assert!(MOUNT_HELP.contains("5 fenced"));
    assert!(MOUNT_HELP.contains("--shutdown-bound <seconds>"));
}

/// Each status line, from the report alone and the store as the operator
/// gave it: a stopped shutdown names what cut it from the recorded cut, a
/// report without counts says so, a read-only mount prints nothing, a
/// writable one with no report says the shutdown did not run, and no line
/// promises automatic recovery of fenced or damaged state. A line that ignored the
/// recorded cut prints the bound for the signal's cut.
/// A daemon's ending as the status line reads it, and the line it prints.
type StatusRow<'a> = (
    Option<(Option<granary_client::ShutdownReport>, &'a Path)>,
    Option<String>,
);

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one table of every status line, each spelled out in full"
)]
fn shutdown_status_lines() {
    use granary_client::{
        FailureClass, Residue, ShutdownCause as C, ShutdownCut, ShutdownOutcome as O,
        ShutdownReport,
    };
    let store = Path::new("rel/store dir");
    let left = Some(Residue {
        files: 3,
        bytes: 912,
        operations: 5,
    });
    let report = |outcome, cut, residue| ShutdownReport {
        outcome,
        cut,
        residue,
        elapsed_ms: 1234,
    };
    let kept = "the overlay, staging and intent are kept in rel/store dir: preserve it; the next \
                mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery";
    let rows: Vec<StatusRow<'_>> =
        vec![
        (None, None),
        (
            Some((None, store)),
            Some(
                "gran mount: the shutdown did not run; the overlay is kept in rel/store dir: \
                 preserve it; the next mount with this store can finish interrupted non-fenced shutdown before serving; fenced or damaged state needs explicit recovery"
                    .to_owned(),
            ),
        ),
        (
            Some((Some(report(O::Committed(9), None, None)), store)),
            Some("gran mount: shutdown committed seq=9 in 1234 ms".to_owned()),
        ),
        (
            Some((Some(report(O::Clean, None, None)), store)),
            Some("gran mount: shutdown had nothing to commit".to_owned()),
        ),
        (
            Some((
                Some(report(O::Incomplete(C::Deadline), Some(ShutdownCut::Bound), left)),
                store,
            )),
            Some(format!(
                "gran mount: shutdown stopped at its bound after 1234 ms: 3 files (912 bytes) \
                 unsynced, 5 operations uncommitted; {kept}"
            )),
        ),
        (
            Some((
                Some(report(O::Incomplete(C::Deadline), Some(ShutdownCut::Signal), left)),
                store,
            )),
            Some(format!(
                "gran mount: shutdown stopped by a signal after 1234 ms: 3 files (912 \
                 bytes) unsynced, 5 operations uncommitted; {kept}"
            )),
        ),
        (
            Some((
                Some(report(
                    O::Incomplete(C::Failed(FailureClass::Unavailable)),
                    None,
                    None,
                )),
                store,
            )),
            Some(format!(
                "gran mount: shutdown failed (unavailable) after 1234 ms: what was left could \
                 not be read; {kept}"
            )),
        ),
        (
            Some((Some(report(O::Incomplete(C::Internal), None, left)), store)),
            Some(format!(
                "gran mount: shutdown lost its sequence after 1234 ms: 3 files (912 bytes) \
                 unsynced, 5 operations uncommitted; {kept}"
            )),
        ),
        (
            Some((Some(report(O::Fenced, None, left)), store)),
            Some(
                "gran mount: shutdown fenced after 1234 ms: 3 files (912 bytes) unsynced, \
                 5 operations uncommitted; the authority refused this mount's \
                 ownership or its commit; the overlay is kept in rel/store dir: preserve it; \
                 recovery is explicit"
                    .to_owned(),
            ),
        ),
    ];
    let mut cases = 0;
    for (ending, expected) in rows {
        let line = shutdown_status_line("gran mount", ending);
        assert!(
            !line
                .as_deref()
                .is_some_and(|line| line.contains("again to finish")),
            "{line:?}"
        );
        assert_eq!(line, expected, "{ending:?}");
        cases += 1;
    }
    assert_eq!(cases, 9);
}

/// A handled-failure arm must RELEASE its readiness sender before it
/// runs its diagnostic, and the three candidate orderings are distinguished
/// from inside the diagnostic itself.
///
/// **This is the decisive portable regression, and it needs no watchdog, no
/// timeout and no scheduling assumption.** The production arms are Linux-only
/// and this host cannot run them; what it CAN run is the one function all four
/// arms funnel through, with the diagnostic injected. A sibling sender is
/// dropped without reporting first, so at the moment the diagnostic begins:
///
/// | ordering | what fails |
/// |---|---|
/// | diagnostic BEFORE send (the shipped bug) | the report is not buffered yet |
/// | send, keep the sender, then diagnostic | the channel is not disconnected |
/// | send, DROP, then diagnostic | neither — both hold |
///
/// The middle row is the one that matters: reporting first is the obvious fix
/// and it is not sufficient, because a thread that has reported and still
/// holds its clone keeps the channel connected, so a sibling dying pre-report
/// disconnects nothing and `await_signal_readiness`'s second read blocks —
/// which is the very hang `report_then_wait` exists to close.
#[test]
fn report_failure_then_releases_its_sender_before_the_diagnostic_runs() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let sibling = tx.clone();
    // The sibling DIES before reporting, which is the condition
    // `await_signal_readiness` has to detect.
    drop(sibling);

    let mut ran = false;
    report_failure_then(tx, || {
        ran = true;
        assert_eq!(
            rx.try_recv(),
            Ok(()),
            "the decided outcome must already be buffered when the diagnostic starts — a \
             diagnostic that blocks before the send is the shipped hang"
        );
        assert_eq!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Disconnected),
            "and this arm's own sender must already be RELEASED, or a blocked diagnostic keeps \
             the channel connected and a sibling's pre-report death stays invisible"
        );
    });
    assert!(
        ran,
        "the diagnostic must run — a fix that swallows it is not a fix"
    );
}

/// The other half, and without it the row above is satisfied by a
/// `report_failure_then` that reports and never returns: the caller's own
/// `return` must still be reached, and nothing may be left in the channel
/// beyond the single decided outcome.
#[test]
fn report_failure_then_sends_exactly_one_report() {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    report_failure_then(tx, || {});
    assert_eq!(rx.try_recv(), Ok(()));
    assert_eq!(
        rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected),
        "exactly one report, and the sender gone with it"
    );
}

#[test]
fn native_writable_opt_in_and_read_only_argument_matrix() {
    let key = root_key_str();
    let manifest = GrainId::of(b"synthetic manifest").to_string();
    let mut cases = 0;
    for mode in [
        vec!["--root-key", key.as_str()],
        vec!["--trust-server"],
        vec!["--manifest-root", manifest.as_str()],
    ] {
        let mut native = mode.clone();
        native.extend([
            "--foreground",
            "--cache-dir",
            "cache",
            "--seq",
            "9",
            "--reset-floor",
            "--uid",
            "17",
            "--gid",
            "18",
        ]);
        let accepted = parse_mount(&mount_argv(&native)).unwrap();
        assert_eq!(
            (
                accepted.writable,
                accepted.key_seed.is_none(),
                accepted.seq,
                accepted.reset_floor,
                accepted.uid,
                accepted.gid
            ),
            (false, true, Some(9), true, Some(17), Some(18))
        );
        for operand in [
            vec!["--key-seed", "seed"],
            vec!["--store-dir", "store"],
            vec!["--contention-rate", "0.25"],
            vec!["--client-cert", "certificate"],
            vec!["--client-key", "tls-key"],
            vec!["--credential-context", "service"],
        ] {
            let mut refused = native.clone();
            refused.extend(operand);
            assert_eq!(
                parse_mount(&mount_argv(&refused)).unwrap_err(),
                "writable operands require --writable"
            );
            cases += 1;
        }
        let helper_mode = if mode[0] == "--root-key" {
            format!("root_key={key}")
        } else if mode[0] == "--trust-server" {
            "trust_server".to_owned()
        } else {
            format!("manifest_root={manifest}")
        };
        let helper = format!(
            "endpoint=https://h,pin={},{helper_mode},foreground,cache_dir=cache",
            a_pin()
        );
        let result =
            parse_mount_gran(&[osstr("v"), osstr("mountpoint"), osstr("-o"), osstr(&helper)]);
        assert_eq!(result.is_ok(), mode[0] == "--root-key");
        cases += 1;
    }
    let writable = parse_mount(&mount_argv(&[
        "--writable",
        "--root-key",
        &key,
        "--key-seed",
        "seed",
        "--store-dir",
        "store",
        "--client-cert",
        "certificate",
        "--client-key",
        "tls-key",
        "--credential-context",
        "service",
        "--cache-dir",
        "cache",
        "--foreground",
        "--reset-floor",
    ]))
    .unwrap();
    assert!(
        writable.writable
            && writable.reset_floor
            && writable.key_seed.is_some()
            && writable.credential.context.is_some()
    );
    assert_eq!(cases, 21);
}

#[test]
fn writable_opt_in_is_a_flag_and_reserved_selectors_reach_common_refusal() {
    let key = root_key_str();
    let read_only = parse_mount(&mount_argv(&[
        "--root-key",
        &key,
        "--cache-dir",
        "--writable",
        "--foreground",
    ]))
    .unwrap();
    assert!(
        !read_only.writable,
        "a path operand cannot opt into writable admission"
    );
    let mut cases = 0;
    for seq in ["0", "18446744073709551615"] {
        let writable = parse_mount(&mount_argv(&[
            "--root-key",
            &key,
            "--seq",
            seq,
            "--writable",
        ]))
        .unwrap();
        assert!(writable.writable && writable.seq.is_some());
        assert!(parse_mount(&mount_argv(&["--root-key", &key, "--seq", seq])).is_err());
        cases += 1;
    }
    assert_eq!(cases, 2);
}

/// `--commit-on-sync` is a valueless writable operand: absent, a writable
/// mount keeps the durable-prepared profile; given, once or twice and in
/// any position, it selects the published one. It swallows no following
/// operand, the writable classifier reads past it, a mount without
/// `--writable` refuses it, and the mount helper's vocabulary has no key
/// for it.
#[test]
fn projected_profile_and_sync_flags() {
    use granary_client::SyncProfile::{DurablePrepared, Published};
    let key = root_key_str();
    let writable = ["--writable", "--root-key", key.as_str()];
    let profile = |extra: &[&str]| {
        parse_mount(&mount_argv(extra)).map(|args| (sync_profile(&args), args.seq, args.cache_dir))
    };
    let mut cases = 0;
    for (extra, expected) in [
        (writable.to_vec(), Ok((DurablePrepared, None, None))),
        (
            [writable.as_slice(), &["--commit-on-sync"]].concat(),
            Ok((Published, None, None)),
        ),
        (
            [
                &["--commit-on-sync"],
                writable.as_slice(),
                &["--commit-on-sync"],
            ]
            .concat(),
            Ok((Published, None, None)),
        ),
        // The value-taking flag after it keeps its own value.
        (
            [
                writable.as_slice(),
                &["--commit-on-sync", "--cache-dir", "cache"],
            ]
            .concat(),
            Ok((Published, None, Some(PathBuf::from("cache")))),
        ),
        // Seq 0 parses only as a writable seq, so the classifier must read
        // `--writable` past the flag before it.
        (
            vec![
                "--seq",
                "0",
                "--commit-on-sync",
                "--writable",
                "--root-key",
                &key,
            ],
            Ok((Published, Some(0), None)),
        ),
        (
            vec!["--root-key", &key, "--commit-on-sync"],
            Err("writable operands require --writable".to_owned()),
        ),
    ] {
        assert_eq!(profile(&extra), expected, "{extra:?}");
        cases += 1;
    }
    let helper = format!(
        "endpoint=https://h,pin={},root_key={key},commit_on_sync",
        a_pin()
    );
    assert_eq!(
        parse_mount_gran(&[osstr("v"), osstr("/mnt"), osstr("-o"), osstr(&helper)]).unwrap_err(),
        "mount.gran: unknown -o option commit_on_sync"
    );
    let opt_in = MOUNT_HELP
        .lines()
        .find(|line| line.trim_start().starts_with("Writable opt-in:"))
        .unwrap();
    assert!(opt_in.contains("--writable [--commit-on-sync]"), "{opt_in}");
    assert_eq!(cases, 6);
}

#[test]
fn writable_retry_rng_uses_process_entropy() {
    let source = include_str!("../attach.rs");
    let body = source
        .split("fn writable_mount_attempt(")
        .nth(1)
        .unwrap()
        .split("pub(crate) fn cmd_mount")
        .next()
        .unwrap();
    assert!(
        body.contains("granary_core::rng::ProcessRng::new()"),
        "production writable retry jitter must use process entropy"
    );
    assert!(!body.contains("SeededRng"));
}

#[test]
fn writable_scope_rejects_invalid_endpoint_and_pin_capacity() {
    use std::cell::RefCell;
    for (endpoint, oversized) in [
        ("https://user@fixture.invalid", false),
        ("https://fixture.invalid", true),
    ] {
        let mut args = parse_mount(&mount_argv(&[
            "--writable",
            "--foreground",
            "--endpoint",
            "https://fixture.invalid",
            "--credential-context",
            "fixture",
            "--pin",
            &a_pin(),
        ]))
        .unwrap();
        args.endpoint = endpoint.to_owned();
        if oversized {
            args.tls_pins = vec![[1; 32]; 1025];
        }
        let output = RefCell::new(String::new());
        let report =
            |message: std::fmt::Arguments<'_>| output.borrow_mut().push_str(&message.to_string());
        let result = writable_mount_attempt(
            &args,
            &process_credentials(),
            None,
            &mut Vec::new(),
            &report,
        );
        assert!(result.is_err());
        assert!(
            output.borrow().contains("WritableScopeRefused"),
            "mount must validate the shared publication scope"
        );
    }
}

#[derive(Debug, Default)]
struct LiveBackend {
    nodes: Vec<granary_fuse::OverlayNode>,
    identities: BTreeMap<u64, Vec<granary_core::manifest::Name>>,
    query_calls: Vec<&'static str>,
    whole_views: usize,
    bound_writes: Vec<(u64, u64, Vec<u8>, bool)>,
    bound_setters: Vec<(u64, Option<u64>, Option<bool>)>,
    boundary: Option<std::sync::Arc<dyn granary_fuse::ViewBoundary>>,
    /// How long its shutdown takes, as a cache close that compacts would.
    close_delay: std::time::Duration,
}
impl SupportBackend for LiveBackend {
    fn bundle_cache(&self) -> Result<BundleCache, BundleRefusal> {
        Ok(BundleCache::ReadOnlyDegraded)
    }
}

fn live_metadata(
    nodes: &[granary_fuse::OverlayNode],
    path: &[granary_core::manifest::Name],
) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
    let node = nodes
        .iter()
        .find(|n| n.path == path)
        .ok_or(granary_fuse::WriteError::Missing)?
        .clone();
    let nlink = if node.kind == granary_vfs::NodeKind::Dir {
        2 + u32::try_from(
            nodes
                .iter()
                .filter(|n| {
                    n.kind == granary_vfs::NodeKind::Dir
                        && n.path.len() == path.len() + 1
                        && n.path.starts_with(path)
                })
                .count(),
        )
        .unwrap()
    } else {
        1
    };
    Ok(granary_fuse::OverlayMetadata {
        inode: node.stage.unwrap_or(0),
        node,
        nlink,
    })
}
impl granary_vfs::GrainFetch for LiveBackend {
    fn grain(&mut self, _: &GrainId, _: u32) -> Result<Vec<u8>, granary_vfs::GrainUnavailable> {
        unreachable!()
    }
}
impl granary_fuse::MountBackend for LiveBackend {
    type DirectoryCursor = (
        Vec<granary_core::manifest::Name>,
        Option<granary_core::manifest::Name>,
    );
    fn overlay_path(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.query_calls.push("path");
        live_metadata(&self.nodes, path)
    }
    fn overlay_lookup(
        &mut self,
        parent: &[granary_core::manifest::Name],
        name: &granary_core::manifest::Name,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.query_calls.push("lookup");
        if live_metadata(&self.nodes, parent)?.node.kind != granary_vfs::NodeKind::Dir {
            return Err(granary_fuse::WriteError::NotDirectory);
        }
        let mut path = parent.to_vec();
        path.push(name.clone());
        live_metadata(&self.nodes, &path)
    }
    fn overlay_directory(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<granary_fuse::OverlayDirectory<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.query_calls.push("directory");
        let directory = live_metadata(&self.nodes, path)?;
        if directory.node.kind != granary_vfs::NodeKind::Dir {
            return Err(granary_fuse::WriteError::NotDirectory);
        }
        let mut parent = path.to_vec();
        parent.pop();
        Ok(granary_fuse::OverlayDirectory {
            directory,
            parent: live_metadata(&self.nodes, &parent)?,
            cursor: (path.to_vec(), None),
        })
    }
    fn overlay_children(
        &mut self,
        cursor: &Self::DirectoryCursor,
    ) -> Result<granary_fuse::OverlayChildren<Self::DirectoryCursor>, granary_fuse::WriteError>
    {
        self.query_calls.push("children");
        let (parent, after) = cursor;
        let mut paths: Vec<_> = self
            .nodes
            .iter()
            .filter(|n| {
                n.path.len() == parent.len() + 1
                    && n.path.starts_with(parent)
                    && n.path.last() > after.as_ref()
            })
            .map(|n| &n.path)
            .collect();
        paths.sort();
        let entries: Vec<_> = paths
            .iter()
            .take(256)
            .map(|p| live_metadata(&self.nodes, p))
            .collect::<Result<_, _>>()?;
        let next = if paths.len() > 256 {
            Some((
                parent.clone(),
                entries.last().and_then(|e| e.node.path.last()).cloned(),
            ))
        } else {
            None
        };
        Ok(granary_fuse::OverlayChildren { entries, next })
    }
    fn overlay_capacity(
        &mut self,
    ) -> Result<granary_fuse::OverlayCapacity, granary_fuse::WriteError> {
        Err(granary_fuse::WriteError::Unimplemented)
    }
    fn overlay_readlink(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.query_calls.push("readlink");
        if live_metadata(&self.nodes, path)?.node.kind != granary_vfs::NodeKind::Symlink {
            return Err(granary_fuse::WriteError::Invalid);
        }
        Ok(b"target".to_vec())
    }
    fn prepare_shrink_retry(
        &mut self,
        _request: granary_fuse::MountShrinkRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        Err(granary_fuse::MountSyncError::InvalidRequest)
    }

    fn prepare_sync(
        &mut self,
        _request: granary_fuse::MountSyncRequest,
    ) -> Result<Box<dyn granary_fuse::MountSyncJob>, granary_fuse::MountSyncError> {
        Err(granary_fuse::MountSyncError::InvalidRequest)
    }

    fn overlay_open(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<Option<u64>, granary_fuse::WriteError> {
        self.query_calls.push("open");
        if live_metadata(&self.nodes, path)?.node.kind != granary_vfs::NodeKind::File {
            return Err(granary_fuse::WriteError::IsDirectory);
        }
        Ok(self
            .identities
            .iter()
            .find_map(|(id, at)| (at == path).then_some(*id)))
    }
    fn overlay_object(
        &mut self,
        object: u64,
    ) -> Result<granary_fuse::OverlayNode, granary_fuse::WriteError> {
        self.query_calls.push("object");
        let path = self
            .identities
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        Ok(live_metadata(&self.nodes, path)?.node)
    }
    fn overlay_close(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.query_calls.push("close");
        self.identities
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        Ok(())
    }
    fn prepare_object(&mut self, object: u64) -> Result<(), granary_fuse::WriteError> {
        self.query_calls.push("prepare_object");
        self.identities
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        Ok(())
    }
    fn prepare_detach(
        &mut self,
        _path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.query_calls.push("prepare_detach");
        Ok(())
    }
    fn read_object(
        &mut self,
        object: u64,
        offset: u64,
        length: usize,
    ) -> Result<Vec<u8>, granary_fuse::WriteError> {
        self.query_calls.push("read");
        let path = self
            .identities
            .get(&object)
            .ok_or(granary_fuse::WriteError::Missing)?;
        let size = live_metadata(&self.nodes, path)?.node.size;
        Ok(vec![
            b'r';
            usize::try_from(
                size.saturating_sub(offset).min(length as u64)
            )
            .unwrap()
        ])
    }
    fn prepare_overlay(
        &mut self,
        path: &[granary_core::manifest::Name],
    ) -> Result<(), granary_fuse::WriteError> {
        self.query_calls.push("prepare_path");
        live_metadata(&self.nodes, path)?;
        Ok(())
    }

    fn mutation_readiness(&mut self) -> Result<(), granary_fuse::MountError> {
        Ok(())
    }
    fn overlay_nodes(
        &mut self,
    ) -> Result<Vec<granary_fuse::OverlayNode>, granary_fuse::WriteError> {
        self.whole_views += 1;
        Ok(self.nodes.clone())
    }
    fn overlay_setattr(
        &mut self,
        path: &[granary_core::manifest::Name],
        size: Option<u64>,
        exec: Option<bool>,
    ) -> Result<granary_fuse::OverlayMetadata, granary_fuse::WriteError> {
        self.query_calls.push("setattr");
        if size.is_some() {
            self.prepare_overlay(path)?;
        }
        self.overlay_mutate(granary_fuse::OverlayMutation::Setattr { path, size, exec })?;
        self.overlay_path(path)
    }
    fn overlay_mutate(
        &mut self,
        operation: granary_fuse::OverlayMutation<'_>,
    ) -> Result<(), granary_fuse::WriteError> {
        use granary_fuse::OverlayMutation as M;
        match operation {
            M::BoundWrite {
                object,
                offset,
                bytes,
                append,
            } => {
                self.query_calls.push("bound_write");
                self.bound_writes
                    .push((object, offset, bytes.to_vec(), append));
                let path = self
                    .identities
                    .get(&object)
                    .ok_or(granary_fuse::WriteError::Missing)?
                    .clone();
                self.overlay_mutate(M::Write {
                    path: &path,
                    offset,
                    bytes,
                    append,
                })?;
            }
            M::BoundSetattr { object, size, exec } => {
                self.query_calls.push("bound_setattr");
                self.bound_setters.push((object, size, exec));
                let path = self
                    .identities
                    .get(&object)
                    .ok_or(granary_fuse::WriteError::Missing)?
                    .clone();
                self.overlay_mutate(M::Setattr {
                    path: &path,
                    size,
                    exec,
                })?;
            }
            M::Create { path, kind, exec } => self.nodes.push(granary_fuse::OverlayNode {
                path: path.to_vec(),
                kind,
                exec,
                size: 0,
                stage: None,
            }),
            M::Write {
                path,
                offset,
                bytes,
                append,
            } => {
                let node = self
                    .nodes
                    .iter_mut()
                    .find(|n| n.path == path)
                    .ok_or(granary_fuse::WriteError::Missing)?;
                let offset = if append { node.size } else { offset };
                node.size = node.size.max(offset + bytes.len() as u64);
            }
            M::Setattr { path, size, exec } => {
                let node = self
                    .nodes
                    .iter_mut()
                    .find(|n| n.path == path)
                    .ok_or(granary_fuse::WriteError::Missing)?;
                if let Some(size) = size {
                    node.size = size;
                }
                if let Some(exec) = exec {
                    node.exec = exec;
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    fn view_boundary(&self) -> Option<std::sync::Arc<dyn granary_fuse::ViewBoundary>> {
        self.boundary.clone()
    }
    fn shutdown(&mut self) -> Result<(), String> {
        pause(self.close_delay);
        Ok(())
    }
    fn abandon(&mut self) {}
}
#[test]
fn daemon_backend_forwards_create_write_and_live_lookup() {
    use granary_fuse::{MountBackend, OverlayMutation as M};
    let mut backend = DaemonBackend {
        session: LiveBackend::default(),
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    let path = vec![granary_core::manifest::Name::new(b"created".to_vec()).unwrap()];
    backend.mutation_readiness().unwrap();
    backend
        .overlay_mutate(M::Create {
            path: &path,
            kind: granary_vfs::NodeKind::File,
            exec: false,
        })
        .unwrap();
    backend
        .overlay_mutate(M::Write {
            path: &path,
            offset: 0,
            bytes: b"bytes",
            append: false,
        })
        .unwrap();
    let metadata = backend.overlay_path(&path).unwrap();
    assert_eq!(
        (
            metadata.node.size,
            metadata.node.kind,
            backend.session.whole_views
        ),
        (5, granary_vfs::NodeKind::File, 0)
    );
}

/// A view install reaches the session the daemon's wrapper owns, through
/// the same adapter the kernel is served from, and the wrapper still
/// records the session's shutdown for `main`.
#[test]
fn daemon_view_binding_reaches_the_session_and_keeps_shutdown_reporting() {
    use granary_fuse::MountBackend as _;
    let built = granary_core::manifest::build_dir(&[]).unwrap();
    let snapshot = granary_vfs::Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        granary_core::manifest::TreeStats::default(),
        granary_vfs::AttrPolicy { uid: 0, gid: 0 },
        granary_fuse::FUSE_SERVE_LIMITS,
    )
    .unwrap();
    let cache_close = std::sync::Arc::default();
    let mut fs = granary_fuse::GranaryFs::new(
        snapshot,
        DaemonBackend {
            session: LiveBackend::default(),
            cache_close: std::sync::Arc::clone(&cache_close),
            exit: std::sync::mpsc::channel().0,
        },
        1,
        granary_fuse::MountWritability::Writable,
    )
    .unwrap();
    let view = fs.view_handle();
    let path = vec![granary_core::manifest::Name::new(b"installed".to_vec()).unwrap()];
    let node = granary_fuse::OverlayNode {
        path: path.clone(),
        kind: granary_vfs::NodeKind::File,
        size: 9,
        exec: false,
        stage: None,
    };
    let installed = view
        .try_install(|daemon, _| daemon_session(daemon).nodes.push(node))
        .is_ok();
    let seen = view
        .try_install(|daemon, _| daemon.overlay_path(&path).map(|seen| seen.node.size))
        .ok();
    fuser::Filesystem::destroy(&mut fs);
    assert_eq!(
        (installed, seen, cache_close.lock().unwrap().clone()),
        (true, Some(Ok(9)), Some(Ok(())))
    );
}

/// The daemon's wrapper hands the adapter its session's own view boundary,
/// so a production mount looks for other writers' heads where its session
/// does.
#[test]
fn daemon_backend_forwards_the_view_boundary() {
    use granary_fuse::MountBackend as _;
    #[derive(Debug)]
    struct Boundary;
    impl granary_fuse::ViewBoundary for Boundary {
        fn wait(
            &self,
            _: granary_fuse::BoundaryKind,
            _: &dyn Fn() -> bool,
        ) -> granary_fuse::BoundaryOutcome {
            granary_fuse::BoundaryOutcome::Served
        }
    }
    let boundary: std::sync::Arc<dyn granary_fuse::ViewBoundary> = std::sync::Arc::new(Boundary);
    let daemon = DaemonBackend {
        session: LiveBackend {
            boundary: Some(boundary.clone()),
            ..LiveBackend::default()
        },
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    let forwarded = daemon.view_boundary();
    assert!(
        forwarded
            .as_ref()
            .is_some_and(|forwarded| std::sync::Arc::ptr_eq(forwarded, &boundary)),
        "the wrapper's boundary is the session's: {forwarded:?}"
    );
}

#[test]
fn daemon_backend_forwards_owned_queries_and_exclusive_continuations() {
    use granary_core::manifest::Name;
    use granary_fuse::{MountBackend as _, OverlayNode, WriteError};
    use granary_vfs::NodeKind;
    let mut fixture = LiveBackend::default();
    fixture.nodes.push(OverlayNode {
        path: vec![],
        kind: NodeKind::Dir,
        size: 4096,
        exec: false,
        stage: None,
    });
    for index in 0..257 {
        let path = vec![Name::new(format!("child-{index:04}").into_bytes()).unwrap()];
        fixture.nodes.push(OverlayNode {
            path,
            kind: NodeKind::File,
            size: 7,
            exec: true,
            stage: None,
        });
    }
    let last = vec![Name::new(b"child-0256".to_vec()).unwrap()];
    fixture.identities.insert(73, last.clone());
    assert_eq!(
        fixture.nodes.len(),
        258,
        "fixture cardinality: {}",
        fixture.nodes.len()
    );
    let mut backend = DaemonBackend {
        session: fixture,
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    assert_eq!(backend.overlay_path(&last).unwrap().node.path, last);
    assert_eq!(
        backend
            .overlay_lookup(&[], last.last().unwrap())
            .unwrap()
            .node
            .path,
        last
    );
    let directory = backend.overlay_directory(&[]).unwrap();
    assert_eq!((directory.directory.nlink, directory.parent.nlink), (2, 2));
    let first = backend.overlay_children(&directory.cursor).unwrap();
    assert_eq!((first.entries.len(), first.next.is_some()), (256, true));
    let last_page = backend.overlay_children(&first.next.unwrap()).unwrap();
    assert_eq!(
        (
            last_page.entries.len(),
            last_page.next.is_none(),
            &last_page.entries.first().unwrap().node.path
        ),
        (1, true, &last)
    );
    let absent = vec![Name::new(b"absent".to_vec()).unwrap()];
    assert_eq!(backend.overlay_path(&absent), Err(WriteError::Missing));
    assert_eq!(
        backend.overlay_lookup(&last, &absent[0]),
        Err(WriteError::NotDirectory)
    );
    assert_eq!(
        backend.overlay_directory(&last).err(),
        Some(WriteError::NotDirectory)
    );
    assert_eq!(
        (backend.session.query_calls, backend.session.whole_views),
        (
            vec![
                "path",
                "lookup",
                "directory",
                "children",
                "children",
                "path",
                "lookup",
                "directory"
            ],
            0
        )
    );
}

#[test]
fn daemon_backend_forwards_empty_and_missing_queries_without_whole_views() {
    use granary_core::manifest::Name;
    use granary_fuse::{MountBackend as _, OverlayNode, WriteError};
    use granary_vfs::NodeKind;
    let empty = vec![Name::new(b"empty".to_vec()).unwrap()];
    let file = vec![Name::new(b"file".to_vec()).unwrap()];
    let missing = Name::new(b"missing".to_vec()).unwrap();
    let mut fixture = LiveBackend::default();
    for (path, kind) in [
        (vec![], NodeKind::Dir),
        (empty.clone(), NodeKind::Dir),
        (file.clone(), NodeKind::File),
    ] {
        fixture.nodes.push(OverlayNode {
            path,
            kind,
            size: 7,
            exec: false,
            stage: None,
        });
    }
    let cardinality = fixture.nodes.len();
    assert_eq!(
        cardinality, 3,
        "CLI nonempty fixture cardinality: {cardinality}"
    );
    let mut backend = DaemonBackend {
        session: fixture,
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    let directory = backend.overlay_directory(&empty).unwrap();
    let page = backend.overlay_children(&directory.cursor).unwrap();
    assert_eq!(
        (page.entries.len(), page.next, directory.directory.nlink),
        (0, None, 2)
    );
    assert_eq!(
        backend.overlay_path(std::slice::from_ref(&missing)),
        Err(WriteError::Missing)
    );
    assert_eq!(
        backend.overlay_lookup(&[], &missing),
        Err(WriteError::Missing)
    );
    assert_eq!(
        backend.overlay_lookup(std::slice::from_ref(&missing), &missing),
        Err(WriteError::Missing)
    );
    assert_eq!(
        backend.overlay_lookup(&file, &missing),
        Err(WriteError::NotDirectory)
    );
    assert_eq!(
        backend
            .overlay_directory(std::slice::from_ref(&missing))
            .err(),
        Some(WriteError::Missing)
    );
    assert_eq!(
        (backend.session.query_calls, backend.session.whole_views),
        (
            vec![
                "directory",
                "children",
                "path",
                "lookup",
                "lookup",
                "lookup",
                "directory"
            ],
            0
        ),
        "every empty/missing/refused query must forward; none may request a whole-tree fallback"
    );
}

#[test]
fn daemon_backend_forwards_unbound_setter_attributes_and_refusals() {
    use granary_core::manifest::Name;
    use granary_fuse::{MountBackend as _, OverlayNode, WriteError};
    use granary_vfs::NodeKind;
    let path = vec![Name::new(b"file".to_vec()).unwrap()];
    let mut fixture = LiveBackend::default();
    fixture.nodes.push(OverlayNode {
        path: path.clone(),
        kind: NodeKind::File,
        size: 7,
        exec: false,
        stage: None,
    });
    assert_eq!(
        fixture.nodes.len(),
        1,
        "nonempty setter fixture: {}",
        fixture.nodes.len()
    );
    let mut backend = DaemonBackend {
        session: fixture,
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    let valid = backend.overlay_setattr(&path, Some(9), Some(true));
    let missing = vec![Name::new(b"absent".to_vec()).unwrap()];
    let refused = backend.overlay_setattr(&missing, Some(1), None);
    assert_eq!(
        (
            valid.map(|m| (m.node.path, m.node.size, m.node.exec, m.nlink)),
            refused,
            backend.session.query_calls,
            backend.session.whole_views
        ),
        (
            Ok((path, 9, true, 1)),
            Err(WriteError::Missing),
            vec!["setattr", "prepare_path", "path", "setattr", "prepare_path"],
            0
        ),
        "actual wrapper must forward both setter results without rebuilding a query"
    );
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one actual wrapper corpus joins exact forwarding arguments, typed refusals and nonzero call counts"
)]
fn daemon_backend_forwards_object_preparation_readlink_and_bound_effects() {
    use granary_core::manifest::Name;
    use granary_fuse::{MountBackend as _, OverlayMutation as M, OverlayNode, WriteError};
    use granary_vfs::NodeKind;
    let file = vec![Name::new(b"file".to_vec()).unwrap()];
    let link = vec![Name::new(b"link".to_vec()).unwrap()];
    let missing = vec![Name::new(b"absent".to_vec()).unwrap()];
    let mut fixture = LiveBackend::default();
    for (path, kind, size) in [
        (file.clone(), NodeKind::File, 7),
        (link.clone(), NodeKind::Symlink, 6),
    ] {
        fixture.nodes.push(OverlayNode {
            path,
            kind,
            size,
            exec: false,
            stage: None,
        });
    }
    fixture.identities.insert(73, file.clone());
    assert_eq!(
        (fixture.nodes.len(), fixture.identities.len()),
        (2, 1),
        "actual CLI fixture: {fixture:?}"
    );
    let mut backend = DaemonBackend {
        session: fixture,
        cache_close: std::sync::Arc::default(),
        exit: std::sync::mpsc::channel().0,
    };
    assert_eq!(
        (
            backend.overlay_readlink(&link),
            backend.overlay_readlink(&file),
            backend.overlay_readlink(&missing)
        ),
        (
            Ok(b"target".to_vec()),
            Err(WriteError::Invalid),
            Err(WriteError::Missing)
        ),
        "readlink success and distinct refusals"
    );
    assert_eq!(
        (
            backend.overlay_open(&file),
            backend.overlay_open(&link),
            backend.overlay_open(&missing)
        ),
        (
            Ok(Some(73)),
            Err(WriteError::IsDirectory),
            Err(WriteError::Missing)
        ),
        "open must preserve the returned object and type/missing refusals"
    );
    assert_eq!(
        (
            backend.prepare_overlay(&file),
            backend.prepare_overlay(&missing),
            backend.prepare_detach(&file),
            backend.prepare_detach(&missing)
        ),
        (Ok(()), Err(WriteError::Missing), Ok(()), Ok(())),
        "preparation, including absent detach, must always forward"
    );
    assert_eq!(
        (
            backend.prepare_object(73),
            backend.prepare_object(74),
            backend.read_object(73, 2, 3),
            backend.read_object(73, 8, 3),
            backend.read_object(74, 0, 3)
        ),
        (
            Ok(()),
            Err(WriteError::Missing),
            Ok(b"rrr".to_vec()),
            Ok(vec![]),
            Err(WriteError::Missing)
        ),
        "bound preparation/ranges/refusals"
    );
    assert_eq!(
        (
            backend.overlay_object(73).map(|n| (n.path, n.size)),
            backend.overlay_object(74)
        ),
        (Ok((file.clone(), 7)), Err(WriteError::Missing)),
        "held metadata and absence"
    );
    assert_eq!(
        (
            backend.overlay_mutate(M::BoundWrite {
                object: 73,
                offset: 8,
                bytes: b"abc",
                append: false
            }),
            backend.overlay_mutate(M::BoundWrite {
                object: 74,
                offset: 8,
                bytes: b"abc",
                append: false
            }),
            backend.overlay_object(73).map(|n| n.size)
        ),
        (Ok(()), Err(WriteError::Missing), Ok(11)),
        "bound write forwards identity, offset and bytes"
    );
    assert_eq!(
        (
            backend.overlay_mutate(M::BoundWrite {
                object: 73,
                offset: 0,
                bytes: b"!",
                append: true
            }),
            backend.overlay_object(73).map(|n| n.size)
        ),
        (Ok(()), Ok(12)),
        "append must preserve its flag and payload"
    );
    assert_eq!(
        (
            backend.overlay_mutate(M::BoundSetattr {
                object: 73,
                size: Some(9),
                exec: Some(true)
            }),
            backend.overlay_mutate(M::BoundSetattr {
                object: 74,
                size: Some(1),
                exec: None
            }),
            backend.overlay_object(73).map(|n| (n.size, n.exec))
        ),
        (Ok(()), Err(WriteError::Missing), Ok((9, true))),
        "bound setter forwards identity and both fields"
    );
    assert_eq!(
        (backend.overlay_close(73), backend.overlay_close(74)),
        (Ok(()), Err(WriteError::Missing)),
        "exact close identity and refusal"
    );
    assert_eq!(
        (
            &backend.session.bound_writes,
            &backend.session.bound_setters
        ),
        (
            &vec![
                (73, 8, b"abc".to_vec(), false),
                (74, 8, b"abc".to_vec(), false),
                (73, 0, b"!".to_vec(), true)
            ],
            &vec![(73, Some(9), Some(true)), (74, Some(1), None)]
        ),
        "nonempty exact forwarded payloads and fields"
    );
    assert_eq!(
        (backend.session.query_calls, backend.session.whole_views),
        (
            vec![
                "readlink",
                "readlink",
                "readlink",
                "open",
                "open",
                "open",
                "prepare_path",
                "prepare_path",
                "prepare_detach",
                "prepare_detach",
                "prepare_object",
                "prepare_object",
                "read",
                "read",
                "read",
                "object",
                "object",
                "bound_write",
                "bound_write",
                "object",
                "bound_write",
                "object",
                "bound_setattr",
                "bound_setattr",
                "object",
                "close",
                "close"
            ],
            0
        ),
        "all 27 actual wrapper calls must reach the fixture, without whole views"
    );
}

#[test]
fn mount_contention_rate_uses_default_and_validated_operator_value() {
    let default = parse_mount(&mount_argv(&["--writable"])).unwrap();
    assert_eq!(
        default.contention_threshold,
        granary_client::ContentionThreshold::parse("0.25").unwrap()
    );
    let mut cases = 0;
    for value in ["0.249", "0.251", "1"] {
        let parsed = parse_mount(&mount_argv(&["--writable", "--contention-rate", value])).unwrap();
        assert_eq!(
            parsed.contention_threshold,
            granary_client::ContentionThreshold::parse(value).unwrap(),
            "{value}"
        );
        cases += 1;
    }
    for value in ["0", "NaN", "inf", "-0.1", "1.1", "bad"] {
        let refused =
            parse_mount(&mount_argv(&["--writable", "--contention-rate", value])).unwrap_err();
        assert_eq!(
            refused, "--contention-rate needs a finite rate greater than 0 and at most 1",
            "{value}"
        );
        cases += 1;
    }
    assert_eq!(cases, 9);
}

#[test]
fn contention_rate_help_belongs_to_writable_opt_in() {
    let writable = MOUNT_HELP
        .lines()
        .find(|line| line.trim_start().starts_with("Writable opt-in:"))
        .unwrap();
    assert!(writable.contains("--contention-rate <rate>"), "{writable}");
    assert_eq!(MOUNT_HELP.matches("--contention-rate").count(), 1);
}

#[cfg(target_os = "linux")]
mod daemon_linux;

#[test]
fn bundle_configuration_projects_presence_counts_and_closed_settings() {
    use granary_core::support::BundleConfiguration;
    let key = root_key_str();
    let mut args = parse_mount(&mount_argv(&[
        "--root-key",
        &key,
        "--cache-dir",
        "synthetic-cache",
    ]))
    .unwrap();
    args.seq = Some(17);
    args.uid = Some(19);
    args.gid = Some(23);
    args.allow_other = true;
    args.foreground = true;
    args.reset_floor = true;
    args.force = true;
    args.key_seed = Some(PathBuf::from("synthetic-seed"));
    args.store_dir = Some(PathBuf::from("synthetic-store"));
    args.writable = true;
    args.contention_threshold = granary_client::ContentionThreshold::parse("0.375").unwrap();
    args.credential.certificate = Some(PathBuf::from("synthetic-certificate"));
    args.credential.key = Some(PathBuf::from("synthetic-key"));
    args.credential.context = Some(
        granary_client::publication_config::CredentialContext::new("synthetic-context").unwrap(),
    );
    args.credential.publishers.push(&key).unwrap();
    let settings = crate::logging::resolve(
        &crate::logging::Flags::default(),
        &|name| match name {
            crate::logging::ENV_FORMAT => Some(osstr("json")),
            crate::logging::ENV_FILE => Some(osstr("synthetic-log")),
            crate::logging::ENV_PATHS => Some(osstr("full")),
            crate::logging::ENV_FILTER => Some(osstr("trace")),
            _ => None,
        },
        &|_| unreachable!(),
    )
    .unwrap();
    let expected = BundleConfiguration {
        mount_mode: 2,
        root_key_configured: true,
        manifest_root_pinned: false,
        trust_server: false,
        tls_pin_count: 1,
        cache_configured: true,
        seq_pinned: true,
        uid_override: true,
        gid_override: true,
        allow_other: true,
        foreground: true,
        reset_floor: true,
        force: true,
        key_seed_configured: true,
        store_dir_configured: true,
        contention_threshold_bits: 0x3fd8_0000_0000_0000,
        certificate_configured: true,
        key_configured: true,
        credential_context_configured: true,
        publisher_key_count: 1,
        wire_snapshot_configured: false,
        log_format: 2,
        log_destination: 2,
        log_paths: 2,
        log_filter_source: 4,
    };
    let result = args.bundle_configuration(&settings);
    assert!(
        result == Ok(expected),
        "support configuration lost a presence/count/class: got {result:?}"
    );
}

#[test]
fn support_cache_observation_maps_only_a_held_gate_to_timed_out() {
    assert_eq!(
        [
            granary_fuse::SlotBusy::Taken,
            granary_fuse::SlotBusy::Poisoned,
            granary_fuse::SlotBusy::Abandoned,
        ]
        .map(support_cache_refusal),
        [
            BundleRefusal::TimedOut,
            BundleRefusal::Unavailable,
            BundleRefusal::Unavailable,
        ]
    );
}

#[test]
fn support_collection_observes_the_backend_without_waiting_for_its_gate() {
    let built = granary_core::manifest::build_dir(&[]).unwrap();
    let snapshot = granary_vfs::Snapshot::new(
        built.nodes.into_iter().collect(),
        built.root,
        granary_core::sheaf::Timestamp { secs: 1, nanos: 0 },
        granary_core::manifest::TreeStats::default(),
        granary_vfs::AttrPolicy { uid: 0, gid: 0 },
        granary_fuse::FUSE_SERVE_LIMITS,
    )
    .unwrap();
    let fs = granary_fuse::GranaryFs::new(
        snapshot,
        DaemonBackend {
            session: LiveBackend::default(),
            cache_close: std::sync::Arc::default(),
            exit: std::sync::mpsc::channel().0,
        },
        1,
        granary_fuse::MountWritability::ReadOnly,
    )
    .unwrap();
    let holder = fs.view_handle();
    let observer = fs.view_handle();
    let owners = crate::support_bundle::LiveOwners {
        configuration: Err(BundleRefusal::Unavailable),
        history: granary_client::BundleHistory::default(),
        metrics: None,
        overlay: None,
    };
    let at = granary_core::sheaf::Timestamp { secs: 2, nanos: 0 };
    let (entered, held) = std::sync::mpsc::sync_channel(0);
    let (release, released) = std::sync::mpsc::sync_channel(0);
    std::thread::scope(|scope| {
        let holding = scope.spawn(move || {
            assert!(
                holder
                    .try_install(|_, _| {
                        entered.send(()).unwrap();
                        released.recv().unwrap();
                    })
                    .is_ok()
            );
        });
        held.recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();
        let contended = collect_support(&observer, &owners, at).unwrap();
        release.send(()).unwrap();
        holding.join().unwrap();
        let healthy = collect_support(&observer, &owners, at).unwrap();
        let status = |archive: &granary_core::support::BundleArchive| {
            archive
                .manifest
                .entries
                .iter()
                .find(|entry| entry.kind == granary_core::support::BundleKind::Cache)
                .unwrap()
                .status
        };
        assert_eq!(
            (status(&contended), status(&healthy)),
            (
                granary_core::support::BundleEntryStatus::Refused(BundleRefusal::TimedOut),
                granary_core::support::BundleEntryStatus::Exported {
                    length: 1,
                    digest: *GrainId::of(&[2]).digest(),
                },
            ),
            "production collection blocked, misclassified the gate, or lost its healthy path"
        );
    });
}

#[test]
fn bundle_configuration_tracks_manifest_wire_and_default_settings() {
    let settings = crate::logging::resolve(
        &crate::logging::Flags::default(),
        &|_| None,
        &|_| unreachable!(),
    )
    .unwrap();
    let mut manifest = parse_mount(&mount_argv(&[
        "--manifest-root",
        &GrainId::of(b"synthetic-manifest").to_string(),
        "--wire-snapshot",
        "synthetic-wire",
        "--wire-run-id",
        "synthetic-run",
        "--wire-role",
        "client-1",
    ]))
    .unwrap();
    let projected = manifest.bundle_configuration(&settings).unwrap();
    assert!(
        (
            projected.manifest_root_pinned,
            projected.root_key_configured,
            projected.trust_server,
            projected.wire_snapshot_configured
        ) == (true, false, false, true),
        "support identity/presence selection drifted"
    );
    manifest.tls_pins.clear();
    assert_eq!(
        manifest
            .bundle_configuration(&settings)
            .unwrap()
            .tls_pin_count,
        0
    );
    let default = parse_mount(&mount_argv(&["--trust-server"])).unwrap();
    let logging = crate::logging::resolve(
        &crate::logging::Flags::default(),
        &|_| None,
        &|_| unreachable!(),
    )
    .unwrap();
    let projected = default.bundle_configuration(&logging).unwrap();
    assert!(
        (
            projected.mount_mode,
            projected.root_key_configured,
            projected.trust_server,
            projected.log_format,
            projected.log_destination,
            projected.log_paths,
            projected.log_filter_source
        ) == (1, false, true, 1, 1, 1, 1),
        "support configuration defaults/classes drifted"
    );
}

#[test]
fn bundle_configuration_refuses_each_unencodable_count_without_saturation() {
    let key = root_key_str();
    let mut args = parse_mount(&mount_argv(&["--root-key", &key])).unwrap();
    let settings = crate::logging::resolve(
        &crate::logging::Flags::default(),
        &|_| None,
        &|_| unreachable!(),
    )
    .unwrap();
    let mut refused = 0;
    let pin = *args.tls_pins.first().unwrap();
    for count in [65535, 65536] {
        args.tls_pins = vec![pin; count];
        let result = args.bundle_configuration(&settings);
        if count == 65535 {
            assert!(
                matches!(result, Ok(p) if p.tls_pin_count == 65535),
                "valid support pin count refused: {result:?}"
            );
        } else {
            refused += 1;
            assert_eq!(
                result.err().map(|e| e.to_string()).as_deref(),
                Some("unencodable"),
                "oversize pin count must refuse before narrowing"
            );
        }
    }
    args.tls_pins.clear();
    for _ in 0..65535 {
        args.credential.publishers.push(&key).unwrap();
    }
    assert_eq!(
        args.bundle_configuration(&settings)
            .unwrap()
            .publisher_key_count,
        65535
    );
    args.credential.publishers.push(&key).unwrap();
    refused += 1;
    assert_eq!(
        args.bundle_configuration(&settings)
            .err()
            .map(|e| e.to_string())
            .as_deref(),
        Some("unencodable"),
        "oversize publisher key count must refuse before narrowing"
    );
    assert_eq!(refused, 2);
}
