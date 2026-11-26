// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::os::unix::fs::MetadataExt as _;
use std::sync::{Arc, Mutex};

use nix::sys::stat::Mode;

use super::super::cli::error_exit;
use super::super::verbs::{TEMP, show_on};
use super::*;
use crate::protected_dir::tests::{Call, Phase, Recorder, is_root};

#[test]
fn debug_grant_refuses_corrupt_oversize_accessible_links_and_nonregular_files() {
    for case in [
        "corrupt",
        "oversize",
        "accessible",
        "writable",
        "symlink",
        "fifo",
    ] {
        let fx = Fx::new();
        let grant = base(GrantScope::Volume(volume("data")));
        let path = fx.dir.join(NAME);
        match case {
            "corrupt" => fx.put_bytes(b"bad record"),
            "oversize" => fx.put_bytes(&[0; 524]),
            "accessible" => {
                fx.put(&grant);
                chmod(&path, 0o640);
            }
            "writable" => {
                fx.put(&grant);
                chmod(&path, 0o620);
            }
            "symlink" => {
                fx.put_bytes(encode_grant(&grant).as_bytes());
                std::fs::rename(&path, fx.base.join("target")).unwrap();
                std::os::unix::fs::symlink(fx.base.join("target"), &path).unwrap();
            }
            "fifo" => {
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let code = match case {
            "corrupt" => "grant-corrupt",
            "oversize" => "grant-oversize",
            "accessible" => "grant-accessible",
            "symlink" => "grant-symlink",
            _ => "grant-unprotected",
        };
        let inode = std::fs::symlink_metadata(&path).unwrap().ino();
        let before = if case == "fifo" { None } else { fx.bytes() };
        for m in [
            issue(GrantScope::Volume(volume("data"))),
            Mutation::Narrow(narrow(GrantScope::Volume(volume("data")))),
            Mutation::Revoke { generation: 2 },
        ] {
            let rec = Recorder::new();
            refused(
                mutate_on(&rec, &fx.dir, OPTIONS, expected(4), &m, &NOW),
                code,
            );
            if case == "oversize" || case == "fifo" {
                assert!(
                    !rec.calls().contains(&Call::ReadAt),
                    "refused before reading"
                );
            }
        }
        refused(show_on(&NixOps, &fx.dir, OPTIONS), code);
        assert_eq!(std::fs::symlink_metadata(&path).unwrap().ino(), inode);
        if case != "fifo" {
            assert_eq!(fx.bytes(), before);
        }
    }
}

#[test]
fn debug_grant_show_is_lock_free_and_missing_is_explicit() {
    let fx = Fx::new();
    let ops = Recorder::new();
    assert_eq!(show_on(&ops, &fx.dir, OPTIONS).unwrap(), None);
    assert_eq!(std::fs::read_dir(&fx.dir).unwrap().count(), 0);
    let grant = base(GrantScope::Volume(volume("data")));
    fx.put(&grant);
    chmod(&fx.dir, 0o500);
    assert_eq!(show_on(&ops, &fx.dir, OPTIONS).unwrap(), Some(grant));
    assert!(
        !ops.calls()
            .iter()
            .any(|call| matches!(call, Call::Lock { .. } | Call::CreateExclAt(_)))
    );
    chmod(&fx.dir, 0o700);
}

#[test]
fn debug_grant_directory_checks_and_replaced_directory_refuse_publication() {
    let fx = Fx::new();
    chmod(&fx.dir, 0o750);
    assert!(matches!(
        apply(
            &fx,
            expected(0),
            &issue(GrantScope::Volume(volume("data"))),
            &NOW
        ),
        Err(Error::Directory(_))
    ));
    chmod(&fx.dir, 0o700);
    let rec = Recorder::with_euid(nix::unistd::geteuid().as_raw().saturating_add(1));
    assert!(matches!(
        show_on(&rec, &fx.dir, OPTIONS),
        Err(Error::Directory(_))
    ));
    let rec = Recorder::new();
    let dir = fx.dir.clone();
    let moved = fx.base.join("moved");
    rec.set_hook(move |call, phase| {
        if matches!(call, Call::Lock { .. }) && phase == Phase::After {
            std::fs::rename(&dir, &moved)?;
            std::fs::create_dir(&dir)?;
            chmod(&dir, 0o700);
        }
        Ok(())
    });
    refused(
        mutate_on(
            &rec,
            &fx.dir,
            OPTIONS,
            expected(0),
            &issue(GrantScope::Volume(volume("data"))),
            &NOW,
        ),
        "directory-replaced",
    );
    assert_eq!(fx.bytes(), None);
    assert!(!fx.base.join("moved").join(NAME).exists());
}

#[test]
fn debug_grant_failed_or_inconsistent_reads_never_overwrite() {
    for case in ["open", "stat", "read", "short", "changed"] {
        let fx = Fx::new();
        fx.put(&base(GrantScope::Volume(volume("data"))));
        let before = fx.bytes();
        let rec = Recorder::new();
        let path = fx.dir.join(NAME);
        let steering = rec.clone();
        let opened = Arc::new(Mutex::new(false));
        let open = Arc::clone(&opened);
        rec.set_hook(move |call, phase| {
            if *call == Call::OpenReadAt(NAME.to_owned()) && phase == Phase::Before {
                if case == "open" {
                    return Err(std::io::Error::other("injected"));
                }
                *open.lock().unwrap() = true;
            }
            if *open.lock().unwrap() && phase == Phase::Before {
                if (case == "stat" && *call == Call::Fstat)
                    || (case == "read" && *call == Call::ReadAt)
                {
                    return Err(std::io::Error::other("injected"));
                }
                if case == "short" && *call == Call::ReadAt {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&path)?
                        .set_len(0)?;
                }
            }
            if case == "changed" && *call == Call::ReadAt && phase == Phase::After {
                steering.set_ctime_skew(1);
            }
            Ok(())
        });
        let e = mutate_on(
            &rec,
            &fx.dir,
            OPTIONS,
            expected(4),
            &Mutation::Revoke { generation: 2 },
            &NOW,
        )
        .unwrap_err();
        if case == "changed" {
            assert!(matches!(e, Error::Refused("grant-changed")));
        } else {
            assert!(matches!(e, Error::Unwritten { .. }));
        }
        assert_eq!(error_exit(&e), 65);
        assert!(!rec.calls().contains(&Call::CreateExclAt(TEMP.to_owned())));
        if case != "short" {
            assert_eq!(fx.bytes(), before);
        }
    }
}

#[test]
fn debug_grant_publication_order_lock_and_leftover_cleanup() {
    let fx = Fx::new();
    std::fs::write(fx.dir.join(TEMP), b"leftover").unwrap();
    let rec = Recorder::new();
    let dir = fx.dir.clone();
    rec.set_hook(move |call, phase| {
        if matches!(call, Call::SyncDir { .. }) && phase == Phase::After {
            assert!(
                nix::fcntl::Flock::lock(
                    std::fs::File::open(&dir).unwrap(),
                    nix::fcntl::FlockArg::LockExclusiveNonblock
                )
                .is_err(),
                "lock held through sync"
            );
        }
        Ok(())
    });
    let grant = mutate_on(
        &rec,
        &fx.dir,
        OPTIONS,
        expected(0),
        &issue(GrantScope::Volume(volume("data"))),
        &NOW,
    )
    .unwrap();
    assert_eq!(
        granary_core::debug_grant::decode_grant(&fx.bytes().unwrap()).unwrap(),
        grant
    );
    assert!(!fx.dir.join(TEMP).exists());
    let calls = rec.calls();
    let lock = calls
        .iter()
        .position(|c| matches!(c, Call::Lock { .. }))
        .unwrap();
    let read = calls
        .iter()
        .position(|c| *c == Call::OpenReadAt(NAME.to_owned()))
        .unwrap();
    assert!(lock < read);
    let start = calls
        .iter()
        .position(|c| *c == Call::CreateExclAt(TEMP.to_owned()))
        .unwrap();
    let tail: Vec<_> = calls[start..]
        .iter()
        .filter(|c| !matches!(c, Call::WriteAt | Call::Fchown { .. }))
        .cloned()
        .collect();
    let ino = |path: &std::path::Path| std::fs::metadata(path).unwrap().ino();
    assert_eq!(
        tail,
        vec![
            Call::CreateExclAt(TEMP.to_owned()),
            Call::Fstat,
            Call::Fchmod {
                mode: Mode::S_IRUSR | Mode::S_IWUSR
            },
            Call::SyncFile {
                ino: ino(&fx.dir.join(NAME))
            },
            Call::RenameAt(TEMP.to_owned(), NAME.to_owned()),
            Call::SyncDir { ino: ino(&fx.dir) },
            Call::SyncDir { ino: ino(&fx.base) }
        ]
    );
    assert_eq!(
        std::fs::metadata(fx.dir.join(NAME)).unwrap().mode() & 0o777,
        0o600
    );
    rec.clear_calls();
    mutate_on(
        &rec,
        &fx.dir,
        OPTIONS,
        expected(1),
        &Mutation::Revoke { generation: 1 },
        &NOW,
    )
    .unwrap();
    assert_eq!(
        rec.calls()
            .iter()
            .filter(|c| matches!(c, Call::SyncDir { .. }))
            .count(),
        1,
        "present file needs no parent sync"
    );
}

#[test]
fn debug_grant_each_publication_failure_has_the_correct_exit_boundary() {
    for (call, phase, code) in [
        (
            Call::Fchmod {
                mode: Mode::S_IRUSR | Mode::S_IWUSR,
            },
            Phase::Before,
            65,
        ),
        (Call::WriteAt, Phase::Before, 65),
        (Call::SyncFile { ino: 0 }, Phase::Before, 65),
        (
            Call::RenameAt(TEMP.to_owned(), NAME.to_owned()),
            Phase::Before,
            74,
        ),
        (
            Call::RenameAt(TEMP.to_owned(), NAME.to_owned()),
            Phase::After,
            74,
        ),
        (Call::SyncDir { ino: 0 }, Phase::Before, 74),
    ] {
        let fx = Fx::new();
        fx.put(&base(GrantScope::Volume(volume("data"))));
        let before = fx.bytes();
        let rec = Recorder::new();
        let wanted = call.clone();
        rec.set_hook(move |c, p| {
            let matches = match (&wanted, c) {
                (Call::SyncFile { .. }, Call::SyncFile { .. })
                | (Call::SyncDir { .. }, Call::SyncDir { .. }) => true,
                _ => *c == wanted,
            };
            if matches && p == phase {
                Err(std::io::Error::other("injected"))
            } else {
                Ok(())
            }
        });
        let e = mutate_on(
            &rec,
            &fx.dir,
            OPTIONS,
            expected(4),
            &Mutation::Revoke { generation: 2 },
            &NOW,
        )
        .unwrap_err();
        assert_eq!(error_exit(&e), code, "{call:?} {phase:?}: {e}");
        if code == 65 || matches!(call, Call::RenameAt(_, _)) && phase == Phase::Before {
            assert_eq!(fx.bytes(), before);
        } else {
            assert_eq!(
                granary_core::debug_grant::decode_grant(&fx.bytes().unwrap())
                    .unwrap()
                    .fields()
                    .action,
                GrantAction::Revoke
            );
        }
        assert!(!fx.dir.join(TEMP).exists());
    }
    let fx = Fx::new();
    let rec = Recorder::new();
    let parent = std::fs::metadata(&fx.base).unwrap().ino();
    rec.set_hook(move |c, p| {
        if *c == (Call::SyncDir { ino: parent }) && p == Phase::Before {
            Err(std::io::Error::other("injected parent sync"))
        } else {
            Ok(())
        }
    });
    let e = mutate_on(
        &rec,
        &fx.dir,
        OPTIONS,
        expected(0),
        &issue(GrantScope::Volume(volume("data"))),
        &NOW,
    )
    .unwrap_err();
    assert_eq!(error_exit(&e), 74);
    assert!(fx.bytes().is_some());
}

#[test]
fn debug_grant_root_assigns_temporary_to_directory_owner_as_root() {
    if !is_root() {
        return;
    }
    let fx = Fx::new();
    nix::unistd::chown(
        &fx.dir,
        Some(nix::unistd::Uid::from_raw(4242)),
        Some(nix::unistd::Gid::from_raw(4343)),
    )
    .unwrap();
    let grant = apply(
        &fx,
        expected(0),
        &issue(GrantScope::Volume(volume("data"))),
        &NOW,
    )
    .unwrap();
    let meta = std::fs::metadata(fx.dir.join(NAME)).unwrap();
    assert_eq!(
        (meta.uid(), meta.gid(), meta.mode() & 0o777),
        (4242, 4343, 0o600)
    );
    assert_eq!(grant.fields().issuer_uid, 0);
    assert_eq!(
        show_on(&Recorder::with_euid(4242), &fx.dir, OPTIONS).unwrap(),
        Some(grant)
    );
    nix::unistd::chown(
        &fx.dir.join(NAME),
        Some(nix::unistd::Uid::from_raw(4343)),
        None,
    )
    .unwrap();
    refused(show_on(&NixOps, &fx.dir, OPTIONS), "grant-unprotected");
}

#[test]
fn debug_grant_lock_cleanup_and_creation_failures_are_unwritten() {
    for wanted in [
        Call::Lock { ino: 0 },
        Call::UnlinkAt(TEMP.to_owned()),
        Call::CreateExclAt(TEMP.to_owned()),
    ] {
        let fx = Fx::new();
        let rec = Recorder::new();
        rec.set_hook(move |c, p| {
            if p == Phase::Before
                && (*c == wanted || matches!((&wanted, c), (Call::Lock { .. }, Call::Lock { .. })))
            {
                Err(std::io::Error::other("injected"))
            } else {
                Ok(())
            }
        });
        let e = mutate_on(
            &rec,
            &fx.dir,
            OPTIONS,
            expected(0),
            &issue(GrantScope::Volume(volume("data"))),
            &NOW,
        )
        .unwrap_err();
        assert!(matches!(e, Error::Unwritten { .. }));
        assert_eq!(error_exit(&e), 65);
        assert_eq!(fx.bytes(), None);
    }
}

#[test]
fn debug_grant_issue_refuses_unusable_enrollment_under_the_lock() {
    for case in [
        "corrupt",
        "oversize",
        "writable",
        "symlink",
        "fifo",
        "unreadable",
    ] {
        let fx = Fx::new();
        fx.enrollment(false);
        let path = fx.dir.join("ENROLLMENT");
        match case {
            "corrupt" => {
                std::fs::write(&path, b"bad set").unwrap();
            }
            "oversize" => {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_len(u64::try_from(granary_core::enrollment::ENCODED_MAX).unwrap() + 1)
                    .unwrap();
            }
            "writable" => chmod(&path, 0o620),
            "symlink" => {
                std::fs::remove_file(&path).unwrap();
                std::os::unix::fs::symlink(fx.base.join("target"), &path).unwrap();
            }
            "fifo" => {
                std::fs::remove_file(&path).unwrap();
                nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
                    .unwrap();
            }
            _ => {}
        }
        let rec = Recorder::new();
        if case == "unreadable" {
            rec.set_hook(|c, p| {
                if *c == Call::OpenReadAt("ENROLLMENT".to_owned()) && p == Phase::Before {
                    Err(std::io::Error::other("injected"))
                } else {
                    Ok(())
                }
            });
        }
        let result = mutate_on(
            &rec,
            &fx.dir,
            OPTIONS,
            expected(0),
            &issue(GrantScope::Principal(id(1))),
            &NOW,
        );
        if case == "unreadable" {
            assert!(matches!(result, Err(Error::Unwritten { .. })));
        } else {
            refused(result, "enrollment-unavailable");
        }
        assert_eq!(fx.bytes(), None);
    }
}

#[test]
fn debug_grant_replaced_path_refuses_before_unlinking_the_leftover_temp() {
    let fx = Fx::new();
    fx.put(&base(GrantScope::Volume(volume("data"))));
    let before = fx.bytes();
    let temp = fx.dir.join(TEMP);
    std::fs::write(&temp, b"leftover bytes").unwrap();
    let ops = Recorder::with_replaced_path();
    refused(
        mutate_on(
            &ops,
            &fx.dir,
            OPTIONS,
            expected(4),
            &Mutation::Revoke { generation: 2 },
            &NOW,
        ),
        "directory-replaced",
    );
    assert!(
        !ops.calls().contains(&Call::UnlinkAt(TEMP.to_owned())),
        "directory-replaced refusal must not unlink the temporary"
    );
    assert_eq!(std::fs::read(&temp).unwrap(), b"leftover bytes");
    assert_eq!(fx.bytes(), before);
}

#[test]
fn debug_grant_failed_path_stat_names_its_own_stage() {
    let fx = Fx::new();
    let temp = fx.dir.join(TEMP);
    std::fs::write(&temp, b"leftover bytes").unwrap();
    let ops = Recorder::new();
    ops.set_hook(|c, p| {
        if *c == Call::StatPath && p == Phase::Before {
            Err(std::io::Error::other("injected path stat"))
        } else {
            Ok(())
        }
    });
    let error = mutate_on(
        &ops,
        &fx.dir,
        OPTIONS,
        expected(0),
        &issue(GrantScope::Volume(volume("data"))),
        &NOW,
    )
    .unwrap_err();
    match &error {
        Error::Unwritten { during, .. } => assert_eq!(*during, "checking the directory path"),
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(error.to_string().contains("checking the directory path"));
    assert!(!error.to_string().contains("reading DEBUG-GRANT"));
    assert_eq!(error_exit(&error), 65);
    assert_eq!(std::fs::read(&temp).unwrap(), b"leftover bytes");
}

#[test]
fn debug_grant_root_publication_fake_chowns_before_writing_and_records_issuer() {
    let fx = Fx::new();
    let ops = Recorder::root_publication(4242, 4343);
    let grant = mutate_on(
        &ops,
        &fx.dir,
        OPTIONS,
        expected(0),
        &issue(GrantScope::Volume(volume("data"))),
        &NOW,
    )
    .unwrap();
    let calls = ops.calls();
    let chown = calls
        .iter()
        .position(|call| {
            *call
                == Call::Fchown {
                    uid: 4242,
                    gid: 4343,
                }
        })
        .expect("temporary must be given to the directory owner and group");
    let write = calls
        .iter()
        .position(|call| *call == Call::WriteAt)
        .expect("temporary was written");
    assert!(chown < write, "fchown must precede the first byte written");
    assert_eq!(
        grant.fields().issuer_uid,
        0,
        "issuer is the injected effective uid"
    );
    assert_eq!(
        granary_core::debug_grant::decode_grant(&fx.bytes().unwrap()).unwrap(),
        grant
    );
}

#[test]
fn debug_grant_temporary_mode_is_explicitly_0600_despite_create_mask() {
    for mode in [Mode::empty(), Mode::from_bits_truncate(0o777)] {
        let fx = Fx::new();
        let ops = Recorder::with_create_mode(mode);
        let grant = mutate_on(
            &ops,
            &fx.dir,
            OPTIONS,
            expected(0),
            &issue(GrantScope::Volume(volume("data"))),
            &NOW,
        )
        .unwrap();
        assert_eq!(
            std::fs::metadata(fx.dir.join(NAME)).unwrap().mode() & 0o777,
            0o600,
            "published permissions must be exactly 0600"
        );
        let calls = ops.calls();
        let chmod = calls
            .iter()
            .position(|c| {
                *c == Call::Fchmod {
                    mode: Mode::S_IRUSR | Mode::S_IWUSR,
                }
            })
            .expect("explicit fchmod");
        let write = calls.iter().position(|c| *c == Call::WriteAt).unwrap();
        assert!(chmod < write, "fchmod must precede the first byte written");
        assert_eq!(
            granary_core::debug_grant::decode_grant(&fx.bytes().unwrap()).unwrap(),
            grant
        );
    }
}
