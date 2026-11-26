// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The Linux venue's runs of the verbs: the real calls on ext4 under
//! `scripts/authority-venue.sh`'s syscall trace, the filesystem type table
//! on a tmpfs, and a verb cut by a power loss before its directory sync.
//!
//! Each is ignored, reads the script's environment, and panics without
//! it: a run that is not the venue's never counts one as passed. None
//! passes the filesystem acknowledgement unless it says so.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::Duration;

use granary_core::enrollment::EnrollmentSet;

use super::super::verbs::{
    ListReport, VerbError, VerbOptions, VerbRefusal, attach_on, list_on, mint_on, revoke_on,
};
use super::{Door, digest, id, one, tenant};
use crate::protected_dir::tests::{Call, Phase, Recorder, chmod};
use crate::protected_dir::{DirOps, FsRole, NixOps, ProtectionError, RuleBroken};

/// The enrollment directory the venue names, on its filesystem.
const ENROLL_ENV: &str = "GRANARY_VENUE_ENROLL";
/// The directory the venue and a run signal each other through, off the
/// filesystem under test: a verb that returns creates
/// `enroll-returned-<verb>` there, and a paused verb `enroll-paused`.
const CONTROL_ENV: &str = "GRANARY_VENUE_CONTROL";
/// Which step of the power-loss arm this is: `cut` or `check`.
const PHASE_ENV: &str = "GRANARY_VENUE_PHASE";
/// The tmpfs arm's directory on a tmpfs, and its directory on ext4 under a
/// tmpfs ancestor.
const ON_TMPFS_ENV: &str = "GRANARY_VENUE_ON_TMPFS";
const UNDER_TMPFS_ENV: &str = "GRANARY_VENUE_UNDER_TMPFS";

const TMPFS_MAGIC: u64 = 0x0102_1994;
const EXT_MAGIC: u64 = 0xEF53;

/// No acknowledgement: the venue's filesystems are the supported ones.
const STRICT: VerbOptions = VerbOptions {
    accept_unsupported_filesystem: false,
};

fn venue(name: &str) -> PathBuf {
    PathBuf::from(std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is unset: this runs only under scripts/authority-venue.sh")
    }))
}

/// A fresh enrollment directory at `dir` and its parent, each 0o700.
fn fresh(dir: &Path) {
    let parent = dir.parent().unwrap();
    let _ = std::fs::remove_dir_all(parent);
    std::fs::create_dir_all(parent).unwrap();
    chmod(parent, 0o700);
    std::fs::create_dir(dir).unwrap();
    chmod(dir, 0o700);
}

/// `statfs`'s type of the filesystem holding `path`.
fn magic(path: &Path) -> u64 {
    NixOps
        .fs_magic(&File::open(path).unwrap())
        .unwrap()
        .expect("Linux has a type table")
}

/// Mark that `verb` returned: a file created in the control directory, an
/// `openat` the trace shows.
fn returned(control: &Path, verb: &str) {
    std::fs::write(control.join(format!("enroll-returned-{verb}")), b"").unwrap();
}

/// The set after the power-loss arm's mint, and after its attach.
fn old_and_new() -> (EnrollmentSet, EnrollmentSet) {
    let old = one(7, "acme", 1);
    let mut new = old.clone();
    new.attach(id(7), digest(2)).unwrap();
    (old, new)
}

/// The traced workload: a first mint (the file missing), then a revoke,
/// each through the real calls, with a mark in the control directory after
/// each verb returns. The venue checks the syscalls' order; this checks
/// the answers.
#[test]
#[ignore = "the Linux venue's: scripts/authority-venue.sh"]
fn the_verbs_over_the_real_calls() {
    let dir = venue(ENROLL_ENV);
    let control = venue(CONTROL_ENV);
    fresh(&dir);
    assert_eq!(magic(&dir), EXT_MAGIC, "{} is not on ext4", dir.display());
    let minted = mint_on(
        &NixOps,
        &dir,
        STRICT,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[7]),
    )
    .unwrap();
    returned(&control, "mint");
    assert_eq!(minted, (id(7), digest(1)));
    assert_eq!(
        revoke_on(&NixOps, &dir, STRICT, digest(1)).unwrap(),
        (id(7), digest(1))
    );
    returned(&control, "revoke");
    let mut expected = one(7, "acme", 1);
    expected.revoke(&digest(1)).unwrap();
    assert_eq!(
        list_on(&NixOps, &dir, STRICT).unwrap(),
        ListReport::Ok(expected)
    );
}

#[track_caller]
fn refused_type(result: Result<impl std::fmt::Debug, VerbError>, dir: &Path) {
    match result {
        Err(VerbError::Refused(VerbRefusal::Directory(ProtectionError::Rule {
            component,
            rule:
                RuleBroken::FilesystemType {
                    magic: Some(TMPFS_MAGIC),
                    role: FsRole::Directory,
                },
        }))) if component == dir => {}
        other => panic!("expected tmpfs refused for the directory, got {other:?}"),
    }
}

/// A directory on a tmpfs is refused by the walk without the
/// acknowledgement, by the verbs and by the server's reader, and nothing is
/// written; with it, the verb runs. A tmpfs ancestor of a directory on
/// ext4 is accepted without it.
#[test]
#[ignore = "the Linux venue's: scripts/authority-venue.sh"]
fn tmpfs_is_refused_for_the_directory_and_taken_as_an_ancestor() {
    let on = venue(ON_TMPFS_ENV);
    let under = venue(UNDER_TMPFS_ENV);
    fresh(&on);
    fresh(&under);
    assert_eq!(
        magic(&on),
        TMPFS_MAGIC,
        "{} is not on a tmpfs",
        on.display()
    );
    let tmpfs_ancestor = under
        .ancestors()
        .skip(1)
        .find(|a| magic(a) == TMPFS_MAGIC)
        .unwrap_or_else(|| panic!("no ancestor of {} is a tmpfs", under.display()))
        .to_path_buf();
    assert_eq!(
        magic(&under),
        EXT_MAGIC,
        "{} is not on ext4",
        under.display()
    );

    refused_type(
        mint_on(
            &NixOps,
            &on,
            STRICT,
            &tenant("acme"),
            digest(1),
            &mut Door::of(&[7]),
        ),
        &on,
    );
    refused_type(list_on(&NixOps, &on, STRICT), &on);
    match super::super::reader::ReaderOn::open(NixOps, &on, false, Duration::from_secs(5)) {
        Err(super::super::reader::ReaderStartError::Directory(ProtectionError::Rule {
            component,
            rule:
                RuleBroken::FilesystemType {
                    magic: Some(TMPFS_MAGIC),
                    role: FsRole::Directory,
                },
        })) if component == on => {}
        Err(other) => panic!("the reader: expected tmpfs refused, got {other:?}"),
        Ok(_) => panic!("the reader opened a directory on tmpfs"),
    }
    let left: Vec<_> = std::fs::read_dir(&on).unwrap().collect();
    assert!(left.is_empty(), "a refused verb wrote {left:?}");
    let acknowledged = VerbOptions {
        accept_unsupported_filesystem: true,
    };
    mint_on(
        &NixOps,
        &on,
        acknowledged,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[7]),
    )
    .unwrap();

    mint_on(
        &NixOps,
        &under,
        STRICT,
        &tenant("acme"),
        digest(1),
        &mut Door::of(&[7]),
    )
    .unwrap();
    assert_eq!(
        list_on(&NixOps, &under, STRICT).unwrap(),
        ListReport::Ok(one(7, "acme", 1))
    );
    super::super::reader::ReaderOn::open(NixOps, &under, false, Duration::from_secs(5))
        .unwrap_or_else(|e| {
            panic!(
                "the reader refused {} under the tmpfs {}: {e}",
                under.display(),
                tmpfs_ancestor.display()
            )
        });
}

/// The power-loss arm, in two processes. `cut`: a mint, which returns, then
/// an attach that stops after its rename, before the enrollment
/// directory's sync, and marks `enroll-paused`; the venue cuts the power
/// there and kills it. It never returns: if it does, it marks
/// `enroll-returned-attach`, which the venue reads as a failure. `check`,
/// after the remount: the name holds the old set or the new one, and the
/// set passes the reader's checks.
#[test]
#[ignore = "the Linux venue's: scripts/authority-venue.sh"]
fn a_power_loss_before_the_directory_sync() {
    let dir = venue(ENROLL_ENV);
    let control = venue(CONTROL_ENV);
    let (old, new) = old_and_new();
    match std::env::var(PHASE_ENV).as_deref() {
        Ok("cut") => {
            fresh(&dir);
            mint_on(
                &NixOps,
                &dir,
                STRICT,
                &tenant("acme"),
                digest(1),
                &mut Door::of(&[7]),
            )
            .unwrap();
            returned(&control, "mint");
            let dir_ino = super::ino(&dir);
            let ops = Recorder::new();
            let paused = control.join("enroll-paused");
            // The pause must fall after the rename: the hook sees the rename
            // complete before it lets the directory's sync stop the verb.
            let renamed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            ops.set_hook(move |call, phase| {
                if matches!(call, Call::RenameAt(_, to) if to == "ENROLLMENT") && phase == Phase::After {
                    renamed.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                if *call == (Call::SyncDir { ino: dir_ino }) && phase == Phase::Before {
                    assert!(
                        renamed.load(std::sync::atomic::Ordering::SeqCst),
                        "the directory's sync came before the rename: the pause would not be after it"
                    );
                    std::fs::write(&paused, b"").unwrap();
                    // Held until the venue kills the process; bounded, so
                    // a venue that never does fails rather than hangs.
                    let (_hold, never) = std::sync::mpsc::channel::<()>();
                    let _ = never.recv_timeout(Duration::from_mins(10));
                    panic!("the venue never cut the power");
                }
                Ok(())
            });
            let _ = attach_on(&ops, &dir, STRICT, id(7), digest(2));
            returned(&control, "attach");
            panic!("the attach returned through a pause it should never leave");
        }
        // The verdict is a mark in the control directory, never a line on a
        // standard stream (the server's sources write none).
        Ok("check") => match list_on(&NixOps, &dir, STRICT).unwrap() {
            ListReport::Ok(set) if set == old => {
                std::fs::write(control.join("enroll-check-old"), b"").unwrap();
            }
            ListReport::Ok(set) if set == new => {
                std::fs::write(control.join("enroll-check-new"), b"").unwrap();
            }
            other => panic!("neither the old set nor the new one: {other:?}"),
        },
        other => panic!("{PHASE_ENV}={other:?}: expected cut or check"),
    }
}
