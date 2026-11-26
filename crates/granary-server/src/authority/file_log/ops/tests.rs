// SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

use nix::sys::stat::SFlag;

use std::cell::RefCell;
use std::fs::FileTimes;
use std::time::{Duration, SystemTime};

use super::*;

fn fixture() -> File {
    File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap()
}

fn inspect(mode: SFlag, swapped: Option<bool>) -> (bool, String, Vec<&'static str>) {
    let file = fixture();
    let mut before = nix::sys::stat::fstat(&file).unwrap();
    before.st_mode = mode.bits();
    let mut after = NixOps.fstat(&file).unwrap();
    if let Some(device) = swapped {
        if device {
            after.dev += 1;
        } else {
            after.ino += 1;
        }
    }
    let calls = RefCell::new(Vec::new());
    let result = inspect_time_entry(
        c"entry-under-test",
        || {
            calls.borrow_mut().push("stat-no-follow");
            Ok(before)
        },
        || {
            calls.borrow_mut().push("open");
            file.try_clone()
        },
        |_| {
            calls.borrow_mut().push("fstat");
            Ok(after)
        },
    );
    (
        result.is_ok(),
        result.err().map(|e| e.to_string()).unwrap_or_default(),
        calls.into_inner(),
    )
}

fn refused_type(mode: SFlag) {
    let (ok, text, _) = inspect(SFlag::S_IFREG, None);
    assert_eq!((ok, text), (true, String::new()));
    let (ok, text, calls) = inspect(mode, None);
    assert_eq!(
        (
            ok,
            text.contains("entry-under-test") && text.contains("not a regular file or directory"),
            calls
        ),
        (false, true, vec!["stat-no-follow"]),
        "entry type {mode:?}: {text}"
    );
}

#[test]
fn symlink_refused_without_open() {
    refused_type(SFlag::S_IFLNK);
}
#[test]
fn fifo_refused_without_open() {
    refused_type(SFlag::S_IFIFO);
}
#[test]
fn character_device_refused_without_open() {
    refused_type(SFlag::S_IFCHR);
}
#[test]
fn block_device_refused_without_open() {
    refused_type(SFlag::S_IFBLK);
}
#[test]
fn socket_refused_without_open() {
    refused_type(SFlag::S_IFSOCK);
}

#[test]
fn entry_identity_swap_refuses() {
    assert!(inspect(SFlag::S_IFREG, None).0);
    for device in [false, true] {
        let (ok, text, calls) = inspect(SFlag::S_IFREG, Some(device));
        assert_eq!(
            (
                ok,
                text.contains("entry-under-test") && text.contains("changed identity"),
                calls
            ),
            (false, true, vec!["stat-no-follow", "open", "fstat"]),
            "device={device}: {text}"
        );
    }
}

#[test]
fn file_ctime_survives_reset_mtime() {
    let state = super::super::tests::state_dir();
    let path = state.join("reset-mtime");
    let file = File::create(&path).unwrap();
    file.set_times(
        FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(100)),
    )
    .unwrap();
    let stat = NixOps.fstat(&file).unwrap();
    assert_eq!(stat.mtime, (100, 0), "reset premise: {stat:?}");
    assert!(stat.ctime > (101, 0), "ctime premise: {stat:?}");
    let ops = StdFileOps::for_verb(&state, true).unwrap();
    let mut times = ops.state_times().unwrap();
    // Isolate the file observation from the newly provisioned root's ctime.
    times.directories = vec![(99, 0)];
    assert_eq!(
        (times.files.clone(), times.check(101).is_err()),
        (vec![stat.mtime.max(stat.ctime)], true),
        "observed {times:?}; file {stat:?}"
    );
    let later_mtime = stat.ctime.0 + 60;
    file.set_times(FileTimes::new().set_modified(
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(later_mtime).unwrap()),
    ))
    .unwrap();
    let stat = NixOps.fstat(&file).unwrap();
    assert!(stat.mtime > stat.ctime, "later-mtime premise: {stat:?}");
    let mut times = ops.state_times().unwrap();
    times.directories = vec![(99, 0)];
    assert_eq!(
        (times.files.clone(), times.check(later_mtime).is_err()),
        (vec![stat.mtime], true),
        "observed {times:?}; file {stat:?}"
    );
}
